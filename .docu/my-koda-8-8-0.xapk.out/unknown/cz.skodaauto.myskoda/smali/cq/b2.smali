.class public abstract Lcq/b2;
.super Lcom/google/android/gms/common/api/internal/BasePendingResult;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llo/e;


# direct methods
.method public constructor <init>(Lko/l;)V
    .locals 2

    .line 1
    sget-object v0, Lbq/g;->a:Lc2/k;

    .line 2
    .line 3
    const-string v1, "GoogleApiClient must not be null"

    .line 4
    .line 5
    invoke-static {p1, v1}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/google/android/gms/common/api/internal/BasePendingResult;-><init>(Lko/l;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "Api must not be null"

    .line 12
    .line 13
    invoke-static {v0, p0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public abstract i(Lko/c;)V
.end method

.method public final j(Lcom/google/android/gms/common/api/Status;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Lcom/google/android/gms/common/api/Status;->x0()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    xor-int/lit8 v0, v0, 0x1

    .line 6
    .line 7
    const-string v1, "Failed result must not be success"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, p1}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->c(Lcom/google/android/gms/common/api/Status;)Lko/p;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-virtual {p0, p1}, Lcom/google/android/gms/common/api/internal/BasePendingResult;->f(Lko/p;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method
