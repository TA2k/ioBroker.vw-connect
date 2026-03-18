.class public interface abstract Lcom/salesforce/marketingcloud/storage/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/storage/f$b;,
        Lcom/salesforce/marketingcloud/storage/f$a;
    }
.end annotation


# virtual methods
.method public abstract a(Lcom/salesforce/marketingcloud/storage/f$a;)I
.end method

.method public abstract a(Ljava/util/List;)I
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation
.end method

.method public abstract a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/storage/f$a;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            "Lcom/salesforce/marketingcloud/storage/f$a;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method

.method public abstract a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;Lcom/salesforce/marketingcloud/util/Crypto;)V
.end method

.method public abstract b()V
.end method

.method public abstract b([Ljava/lang/String;)V
.end method

.method public abstract c(Ljava/lang/String;)V
.end method

.method public abstract d(Ljava/lang/String;)V
.end method

.method public abstract e(Ljava/lang/String;)Z
.end method

.method public abstract f(Ljava/lang/String;)Lcom/salesforce/marketingcloud/storage/f$b;
.end method

.method public abstract h()I
.end method

.method public abstract i()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/storage/f$b;",
            ">;"
        }
    .end annotation
.end method

.method public abstract j()V
.end method

.method public abstract m(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation
.end method
