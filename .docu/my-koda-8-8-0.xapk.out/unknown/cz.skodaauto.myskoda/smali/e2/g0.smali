.class public abstract Le2/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/m;

.field public static final b:Lc1/b2;

.field public static final c:J

.field public static final d:Lc1/f1;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lc1/m;

    .line 2
    .line 3
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 4
    .line 5
    invoke-direct {v0, v1, v1}, Lc1/m;-><init>(FF)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Le2/g0;->a:Lc1/m;

    .line 9
    .line 10
    new-instance v0, Ldj/a;

    .line 11
    .line 12
    const/16 v1, 0x13

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Ldj/a;

    .line 18
    .line 19
    const/16 v2, 0x14

    .line 20
    .line 21
    invoke-direct {v1, v2}, Ldj/a;-><init>(I)V

    .line 22
    .line 23
    .line 24
    new-instance v2, Lc1/b2;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lc1/b2;-><init>(Lay0/k;Lay0/k;)V

    .line 27
    .line 28
    .line 29
    sput-object v2, Le2/g0;->b:Lc1/b2;

    .line 30
    .line 31
    const v0, 0x3c23d70a    # 0.01f

    .line 32
    .line 33
    .line 34
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    int-to-long v1, v1

    .line 39
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    int-to-long v3, v0

    .line 44
    const/16 v0, 0x20

    .line 45
    .line 46
    shl-long v0, v1, v0

    .line 47
    .line 48
    const-wide v5, 0xffffffffL

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    and-long v2, v3, v5

    .line 54
    .line 55
    or-long/2addr v0, v2

    .line 56
    sput-wide v0, Le2/g0;->c:J

    .line 57
    .line 58
    new-instance v2, Lc1/f1;

    .line 59
    .line 60
    new-instance v3, Ld3/b;

    .line 61
    .line 62
    invoke-direct {v3, v0, v1}, Ld3/b;-><init>(J)V

    .line 63
    .line 64
    .line 65
    const/4 v0, 0x3

    .line 66
    invoke-direct {v2, v3, v0}, Lc1/f1;-><init>(Ljava/lang/Object;I)V

    .line 67
    .line 68
    .line 69
    sput-object v2, Le2/g0;->d:Lc1/f1;

    .line 70
    .line 71
    return-void
.end method
