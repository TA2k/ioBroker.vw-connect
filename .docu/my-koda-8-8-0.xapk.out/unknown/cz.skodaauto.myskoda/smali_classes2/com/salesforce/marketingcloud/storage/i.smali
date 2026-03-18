.class public interface abstract Lcom/salesforce/marketingcloud/storage/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# virtual methods
.method public abstract a(Ljava/lang/String;)I
.end method

.method public abstract a(Ljava/lang/String;I)I
.end method

.method public abstract a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Message;
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/messages/Message;Lcom/salesforce/marketingcloud/util/Crypto;)V
.end method

.method public abstract b(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Message;",
            ">;"
        }
    .end annotation
.end method

.method public abstract e(I)I
.end method
