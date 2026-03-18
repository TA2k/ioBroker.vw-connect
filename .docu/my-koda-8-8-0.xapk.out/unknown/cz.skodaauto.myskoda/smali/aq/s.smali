.class public final Laq/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/e;


# instance fields
.field public final d:Laq/k;


# direct methods
.method public synthetic constructor <init>(Laq/k;)V
    .locals 0

    .line 1
    iput-object p1, p0, Laq/s;->d:Laq/k;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public z(Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    iget v0, p1, Lcom/google/android/gms/common/api/Status;->d:I

    .line 4
    .line 5
    iget-object p0, p0, Laq/s;->d:Laq/k;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/16 v1, 0xfa1

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance v0, Lko/e;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lko/e;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_1
    :goto_0
    const/4 p1, 0x0

    .line 24
    invoke-virtual {p0, p1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
