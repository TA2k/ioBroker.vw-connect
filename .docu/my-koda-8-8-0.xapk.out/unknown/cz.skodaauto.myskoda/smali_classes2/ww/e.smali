.class public final Lww/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic d:[Lhy0/z;


# instance fields
.field public final a:Landroid/content/SharedPreferences;

.field public final b:Lb81/d;

.field public final c:Lb81/d;


# direct methods
.method public static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lkotlin/jvm/internal/r;

    .line 2
    .line 3
    const-class v1, Lww/e;

    .line 4
    .line 5
    const-string v2, "_lastUpdate"

    .line 6
    .line 7
    const-string v3, "get_lastUpdate()Ljava/lang/String;"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v1, v2, v3, v4}, Lkotlin/jvm/internal/r;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v3, "_uniqueId"

    .line 20
    .line 21
    const-string v5, "get_uniqueId()Ljava/lang/String;"

    .line 22
    .line 23
    invoke-static {v1, v3, v5, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    const/4 v2, 0x2

    .line 28
    new-array v2, v2, [Lhy0/z;

    .line 29
    .line 30
    aput-object v0, v2, v4

    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    aput-object v1, v2, v0

    .line 34
    .line 35
    sput-object v2, Lww/e;->d:[Lhy0/z;

    .line 36
    .line 37
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const-string v1, "PREF_UNIQUE_ID"

    .line 6
    .line 7
    invoke-virtual {p1, v1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    const-string v0, "context.getSharedPrefere\u2026D\", Context.MODE_PRIVATE)"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lww/e;->a:Landroid/content/SharedPreferences;

    .line 17
    .line 18
    new-instance p1, Lb81/d;

    .line 19
    .line 20
    const/16 v0, 0x1a

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    const-string v3, "PREF_LAST_UPDATE"

    .line 24
    .line 25
    invoke-direct {p1, p0, v3, v2, v0}, Lb81/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Lww/e;->b:Lb81/d;

    .line 29
    .line 30
    new-instance p1, Lb81/d;

    .line 31
    .line 32
    invoke-direct {p1, p0, v1, v2, v0}, Lb81/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lww/e;->c:Lb81/d;

    .line 36
    .line 37
    return-void
.end method
