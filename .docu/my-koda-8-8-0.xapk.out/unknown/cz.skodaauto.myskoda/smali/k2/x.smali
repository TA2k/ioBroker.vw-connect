.class public abstract Lk2/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lc1/s;

.field public static final b:Lc1/s;

.field public static final c:Lc1/s;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lc1/s;

    .line 2
    .line 3
    const v1, 0x3e4ccccd    # 0.2f

    .line 4
    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/high16 v3, 0x3f800000    # 1.0f

    .line 8
    .line 9
    invoke-direct {v0, v1, v2, v2, v3}, Lc1/s;-><init>(FFFF)V

    .line 10
    .line 11
    .line 12
    new-instance v0, Lc1/s;

    .line 13
    .line 14
    const v4, 0x3f4ccccd    # 0.8f

    .line 15
    .line 16
    .line 17
    const v5, 0x3e19999a    # 0.15f

    .line 18
    .line 19
    .line 20
    const v6, 0x3e99999a    # 0.3f

    .line 21
    .line 22
    .line 23
    invoke-direct {v0, v6, v2, v4, v5}, Lc1/s;-><init>(FFFF)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lk2/x;->a:Lc1/s;

    .line 27
    .line 28
    new-instance v0, Lc1/s;

    .line 29
    .line 30
    const v4, 0x3f333333    # 0.7f

    .line 31
    .line 32
    .line 33
    const v5, 0x3dcccccd    # 0.1f

    .line 34
    .line 35
    .line 36
    const v7, 0x3d4ccccd    # 0.05f

    .line 37
    .line 38
    .line 39
    invoke-direct {v0, v7, v4, v5, v3}, Lc1/s;-><init>(FFFF)V

    .line 40
    .line 41
    .line 42
    sput-object v0, Lk2/x;->b:Lc1/s;

    .line 43
    .line 44
    new-instance v0, Lc1/s;

    .line 45
    .line 46
    const v4, 0x3ecccccd    # 0.4f

    .line 47
    .line 48
    .line 49
    invoke-direct {v0, v4, v2, v1, v3}, Lc1/s;-><init>(FFFF)V

    .line 50
    .line 51
    .line 52
    new-instance v0, Lc1/s;

    .line 53
    .line 54
    invoke-direct {v0, v4, v2, v3, v3}, Lc1/s;-><init>(FFFF)V

    .line 55
    .line 56
    .line 57
    new-instance v0, Lc1/s;

    .line 58
    .line 59
    invoke-direct {v0, v2, v2, v1, v3}, Lc1/s;-><init>(FFFF)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lc1/s;

    .line 63
    .line 64
    invoke-direct {v0, v2, v2, v3, v3}, Lc1/s;-><init>(FFFF)V

    .line 65
    .line 66
    .line 67
    new-instance v0, Lc1/s;

    .line 68
    .line 69
    invoke-direct {v0, v1, v2, v2, v3}, Lc1/s;-><init>(FFFF)V

    .line 70
    .line 71
    .line 72
    sput-object v0, Lk2/x;->c:Lc1/s;

    .line 73
    .line 74
    new-instance v0, Lc1/s;

    .line 75
    .line 76
    invoke-direct {v0, v6, v2, v3, v3}, Lc1/s;-><init>(FFFF)V

    .line 77
    .line 78
    .line 79
    new-instance v0, Lc1/s;

    .line 80
    .line 81
    invoke-direct {v0, v2, v2, v2, v3}, Lc1/s;-><init>(FFFF)V

    .line 82
    .line 83
    .line 84
    return-void
.end method
