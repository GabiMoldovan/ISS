USE MotoShop;
GO

/*
CREATE TABLE Users (
    UserID INT PRIMARY KEY IDENTITY,
    Username NVARCHAR(50) NOT NULL,
    Email NVARCHAR(100) NOT NULL,
    Password NVARCHAR(100) NOT NULL
);

CREATE TABLE Products (
    ProductID INT PRIMARY KEY IDENTITY,
    Name NVARCHAR(100) NOT NULL,
    Description NVARCHAR(MAX),
    Price DECIMAL(10, 2) NOT NULL,
    StockQuantity INT NOT NULL
);

CREATE TABLE ShoppingCarts (
    CartID INT PRIMARY KEY IDENTITY,
    UserID INT NOT NULL,
    ProductID INT NOT NULL,
    Quantity INT NOT NULL,
    CONSTRAINT FK_Users_Carts FOREIGN KEY (UserID) REFERENCES Users(UserID),
    CONSTRAINT FK_Products_Carts FOREIGN KEY (ProductID) REFERENCES Products(ProductID)
);
*/