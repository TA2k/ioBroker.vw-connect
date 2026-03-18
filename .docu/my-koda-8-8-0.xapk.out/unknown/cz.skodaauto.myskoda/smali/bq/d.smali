.class public final Lbq/d;
.super Lmo/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/p;


# instance fields
.field public final g:Lcom/google/android/gms/common/api/Status;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/common/data/DataHolder;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lmo/c;-><init>(Lcom/google/android/gms/common/data/DataHolder;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lcom/google/android/gms/common/api/Status;

    .line 5
    .line 6
    iget p1, p1, Lcom/google/android/gms/common/data/DataHolder;->h:I

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p1, v1, v1, v1}, Lcom/google/android/gms/common/api/Status;-><init>(ILjava/lang/String;Landroid/app/PendingIntent;Ljo/b;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lbq/d;->g:Lcom/google/android/gms/common/api/Status;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic g(II)Ljava/lang/Object;
    .locals 1

    .line 1
    new-instance v0, Lcq/s;

    .line 2
    .line 3
    iget-object p0, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 4
    .line 5
    invoke-direct {v0, p0, p1, p2}, Lcq/s;-><init>(Lcom/google/android/gms/common/data/DataHolder;II)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final getStatus()Lcom/google/android/gms/common/api/Status;
    .locals 0

    .line 1
    iget-object p0, p0, Lbq/d;->g:Lcom/google/android/gms/common/api/Status;

    .line 2
    .line 3
    return-object p0
.end method
