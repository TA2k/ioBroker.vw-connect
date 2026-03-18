.class public final Lk4/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# static fields
.field public static final e:Lk4/x;

.field public static final f:Lk4/x;

.field public static final g:Lk4/x;

.field public static final h:Lk4/x;

.field public static final i:Lk4/x;

.field public static final j:Lk4/x;

.field public static final k:Lk4/x;

.field public static final l:Lk4/x;

.field public static final m:Lk4/x;

.field public static final n:Lk4/x;

.field public static final o:Ljava/util/List;


# instance fields
.field public final d:I


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lk4/x;

    .line 2
    .line 3
    const/16 v1, 0x64

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lk4/x;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lk4/x;

    .line 9
    .line 10
    const/16 v2, 0xc8

    .line 11
    .line 12
    invoke-direct {v1, v2}, Lk4/x;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v2, Lk4/x;

    .line 16
    .line 17
    const/16 v3, 0x12c

    .line 18
    .line 19
    invoke-direct {v2, v3}, Lk4/x;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sput-object v2, Lk4/x;->e:Lk4/x;

    .line 23
    .line 24
    new-instance v3, Lk4/x;

    .line 25
    .line 26
    const/16 v4, 0x190

    .line 27
    .line 28
    invoke-direct {v3, v4}, Lk4/x;-><init>(I)V

    .line 29
    .line 30
    .line 31
    sput-object v3, Lk4/x;->f:Lk4/x;

    .line 32
    .line 33
    new-instance v4, Lk4/x;

    .line 34
    .line 35
    const/16 v5, 0x1f4

    .line 36
    .line 37
    invoke-direct {v4, v5}, Lk4/x;-><init>(I)V

    .line 38
    .line 39
    .line 40
    sput-object v4, Lk4/x;->g:Lk4/x;

    .line 41
    .line 42
    new-instance v5, Lk4/x;

    .line 43
    .line 44
    const/16 v6, 0x258

    .line 45
    .line 46
    invoke-direct {v5, v6}, Lk4/x;-><init>(I)V

    .line 47
    .line 48
    .line 49
    sput-object v5, Lk4/x;->h:Lk4/x;

    .line 50
    .line 51
    new-instance v6, Lk4/x;

    .line 52
    .line 53
    const/16 v7, 0x2bc

    .line 54
    .line 55
    invoke-direct {v6, v7}, Lk4/x;-><init>(I)V

    .line 56
    .line 57
    .line 58
    sput-object v6, Lk4/x;->i:Lk4/x;

    .line 59
    .line 60
    new-instance v7, Lk4/x;

    .line 61
    .line 62
    const/16 v8, 0x320

    .line 63
    .line 64
    invoke-direct {v7, v8}, Lk4/x;-><init>(I)V

    .line 65
    .line 66
    .line 67
    new-instance v8, Lk4/x;

    .line 68
    .line 69
    const/16 v9, 0x384

    .line 70
    .line 71
    invoke-direct {v8, v9}, Lk4/x;-><init>(I)V

    .line 72
    .line 73
    .line 74
    sput-object v8, Lk4/x;->j:Lk4/x;

    .line 75
    .line 76
    sput-object v2, Lk4/x;->k:Lk4/x;

    .line 77
    .line 78
    sput-object v3, Lk4/x;->l:Lk4/x;

    .line 79
    .line 80
    sput-object v4, Lk4/x;->m:Lk4/x;

    .line 81
    .line 82
    sput-object v6, Lk4/x;->n:Lk4/x;

    .line 83
    .line 84
    filled-new-array/range {v0 .. v8}, [Lk4/x;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    sput-object v0, Lk4/x;->o:Ljava/util/List;

    .line 93
    .line 94
    return-void
.end method

.method public constructor <init>(I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lk4/x;->d:I

    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    const/4 v0, 0x1

    .line 8
    if-gt v0, p1, :cond_0

    .line 9
    .line 10
    const/16 v1, 0x3e9

    .line 11
    .line 12
    if-ge p1, v1, :cond_0

    .line 13
    .line 14
    move p0, v0

    .line 15
    :cond_0
    if-nez p0, :cond_1

    .line 16
    .line 17
    new-instance p0, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string v0, "Font weight can be in range [1, 1000]. Current value: "

    .line 20
    .line 21
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, Lm4/a;->a(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method


# virtual methods
.method public final a(Lk4/x;)I
    .locals 0

    .line 1
    iget p0, p0, Lk4/x;->d:I

    .line 2
    .line 3
    iget p1, p1, Lk4/x;->d:I

    .line 4
    .line 5
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lk4/x;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lk4/x;->a(Lk4/x;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lk4/x;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lk4/x;

    .line 12
    .line 13
    iget p1, p1, Lk4/x;->d:I

    .line 14
    .line 15
    iget p0, p0, Lk4/x;->d:I

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lk4/x;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "FontWeight(weight="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget p0, p0, Lk4/x;->d:I

    .line 9
    .line 10
    const/16 v1, 0x29

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method
