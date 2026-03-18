.class public final synthetic Lcom/google/android/gms/internal/measurement/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# static fields
.field public static final synthetic a:Lcom/google/android/gms/internal/measurement/e1;


# direct methods
.method public static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/gms/internal/measurement/e1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/e1;->a:Lcom/google/android/gms/internal/measurement/e1;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance p0, Lcom/google/android/gms/internal/measurement/y5;

    .line 2
    .line 3
    const-string v0, "internal.platform"

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    invoke-direct {p0, v0, v1}, Lcom/google/android/gms/internal/measurement/y5;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v0, Lcom/google/android/gms/internal/measurement/y5;

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    const-string v2, "getVersion"

    .line 13
    .line 14
    invoke-direct {v0, v2, v1}, Lcom/google/android/gms/internal/measurement/y5;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcom/google/android/gms/internal/measurement/i;->e:Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {v1, v2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    return-object p0
.end method
