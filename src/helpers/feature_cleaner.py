import numpy as np
from sklearn.feature_selection import VarianceThreshold


class FeatureCleaner:
    def __init__(
        self,
        variance_threshold=0.01,
        correlation_threshold=0.9,
        missing_threshold=1.0,
        num_replacement=-1,
        cat_replacement="unknown",
    ):
        """
        Initializes the FeatureCleaner with configurable thresholds and replacement values.

        Parameters:
            variance_threshold (float): Minimum variance for a feature to be kept.
            correlation_threshold (float): Maximum correlation for a feature to be kept.
            missing_threshold (float): Maximum proportion of missing values allowed in a column.
            num_replacement (int/float): Replacement value for missing numerical values.
            cat_replacement (str): Replacement value for missing categorical values.
        """
        self.variance_threshold = variance_threshold
        self.correlation_threshold = correlation_threshold
        self.missing_threshold = missing_threshold
        self.num_replacement = num_replacement
        self.cat_replacement = cat_replacement

    def remove_low_variance(self, df):
        """
        Removes features from the DataFrame with variance lower than the specified threshold.

        Parameters:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            pd.DataFrame: DataFrame with low-variance features dropped.
        """
        numerical_df = df.select_dtypes(include=["number"])
        selector = VarianceThreshold(threshold=self.variance_threshold)
        selector.fit(numerical_df)
        to_drop = numerical_df.columns[~selector.get_support()]
        return df.drop(columns=to_drop)

    def replace_missing_values(self, df):
        """
        Replaces missing values in a DataFrame.
        - Numerical columns: Replace with a specified value (default -1).
        - Categorical columns: Replace with a specified value (default "unknown").

        Parameters:
            df (pd.DataFrame): Input DataFrame with missing values.

        Returns:
            pd.DataFrame: DataFrame with missing values replaced.
        """
        num_cols = df.select_dtypes(include=["number"]).columns
        df[num_cols] = df[num_cols].fillna(self.num_replacement)

        cat_cols = df.select_dtypes(include=["object", "category"]).columns
        df[cat_cols] = df[cat_cols].fillna(self.cat_replacement)

        return df

    def remove_high_correlation(self, df):
        """
        Removes features that have a correlation greater than the specified threshold with any other feature.

        Parameters:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            pd.DataFrame: DataFrame with highly correlated features dropped.
        """
        numerical_df = df.select_dtypes(include=["number"])
        corr_matrix = numerical_df.corr().abs()
        upper_triangle = corr_matrix.where(
            np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
        )
        to_drop = [
            column
            for column in upper_triangle.columns
            if any(upper_triangle[column] > self.correlation_threshold)
        ]
        return df.drop(columns=to_drop)

    def handle_missing_values(self, df):
        """
        Removes columns from the DataFrame that have missing values above a specified threshold.

        Parameters:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            pd.DataFrame: DataFrame with columns containing excessive missing values dropped.
        """
        missing_percentage = df.isnull().mean()
        return df.loc[:, missing_percentage < self.missing_threshold]

    def clean_features(self, df):
        """
        Full feature cleaning pipeline: applies multiple cleaning steps to the input DataFrame.

        The pipeline includes:
        1. Handling missing values by removing columns with too many missing values.
        2. Replacing missing values with specified replacements.
        3. Removing low variance features.
        4. Removing highly correlated features.

        Parameters:
            df (pd.DataFrame): Input DataFrame.

        Returns:
            pd.DataFrame: Cleaned DataFrame after applying all cleaning steps.
        """
        df = self.handle_missing_values(df)
        df = self.replace_missing_values(df)
        df = self.remove_low_variance(df)
        df = self.remove_high_correlation(df)
        return df
