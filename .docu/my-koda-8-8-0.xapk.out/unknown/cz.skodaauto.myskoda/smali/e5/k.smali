.class public final enum Le5/k;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Ljava/util/HashMap;

.field public static final synthetic e:[Le5/k;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Le5/k;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    new-instance v1, Le5/k;

    .line 10
    .line 11
    const-string v3, "CHAIN"

    .line 12
    .line 13
    const/4 v4, 0x1

    .line 14
    invoke-direct {v1, v3, v4}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 15
    .line 16
    .line 17
    new-instance v3, Le5/k;

    .line 18
    .line 19
    const-string v4, "ALIGNED"

    .line 20
    .line 21
    const/4 v5, 0x2

    .line 22
    invoke-direct {v3, v4, v5}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    filled-new-array {v0, v1, v3}, [Le5/k;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    sput-object v4, Le5/k;->e:[Le5/k;

    .line 30
    .line 31
    new-instance v4, Ljava/util/HashMap;

    .line 32
    .line 33
    invoke-direct {v4}, Ljava/util/HashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    new-instance v6, Ljava/util/HashMap;

    .line 37
    .line 38
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 39
    .line 40
    .line 41
    sput-object v6, Le5/k;->d:Ljava/util/HashMap;

    .line 42
    .line 43
    const-string v7, "none"

    .line 44
    .line 45
    invoke-virtual {v4, v7, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    const-string v0, "chain"

    .line 49
    .line 50
    invoke-virtual {v4, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    const-string v1, "aligned"

    .line 54
    .line 55
    invoke-virtual {v4, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    const/4 v3, 0x3

    .line 59
    invoke-static {v2, v6, v7, v3, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 60
    .line 61
    .line 62
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {v6, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Le5/k;
    .locals 1

    .line 1
    const-class v0, Le5/k;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Le5/k;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Le5/k;
    .locals 1

    .line 1
    sget-object v0, Le5/k;->e:[Le5/k;

    .line 2
    .line 3
    invoke-virtual {v0}, [Le5/k;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Le5/k;

    .line 8
    .line 9
    return-object v0
.end method
