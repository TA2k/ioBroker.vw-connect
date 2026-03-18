.class public final Lcq/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/p;


# instance fields
.field public final d:Lcom/google/android/gms/common/api/Status;

.field public final e:Lbq/b;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/api/Status;Lbq/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcq/n;->d:Lcom/google/android/gms/common/api/Status;

    .line 5
    .line 6
    iput-object p2, p0, Lcq/n;->e:Lbq/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getStatus()Lcom/google/android/gms/common/api/Status;
    .locals 0

    .line 1
    iget-object p0, p0, Lcq/n;->d:Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    return-object p0
.end method
