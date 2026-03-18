.class public interface abstract Lcom/salesforce/marketingcloud/storage/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# virtual methods
.method public abstract a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;
.end method

.method public abstract a(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            ">;"
        }
    .end annotation
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)V
.end method

.method public abstract a(Ljava/lang/String;Z)V
.end method

.method public abstract c(Ljava/lang/String;I)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I)",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract d(I)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end method

.method public abstract f(I)I
.end method

.method public abstract l(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/Region;
.end method

.method public abstract l()V
.end method
