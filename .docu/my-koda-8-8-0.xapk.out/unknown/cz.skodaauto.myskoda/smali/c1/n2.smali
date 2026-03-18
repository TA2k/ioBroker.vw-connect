.class public abstract Lc1/n2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    const/high16 v0, 0x3f000000    # 0.5f

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lc1/d;->k:Lc1/b2;

    .line 8
    .line 9
    const/high16 v2, 0x3f800000    # 1.0f

    .line 10
    .line 11
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    new-instance v3, Llx0/l;

    .line 16
    .line 17
    invoke-direct {v3, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    sget-object v1, Lc1/d;->q:Lc1/b2;

    .line 21
    .line 22
    new-instance v4, Llx0/l;

    .line 23
    .line 24
    invoke-direct {v4, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    sget-object v1, Lc1/d;->p:Lc1/b2;

    .line 28
    .line 29
    new-instance v5, Llx0/l;

    .line 30
    .line 31
    invoke-direct {v5, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    sget-object v1, Lc1/d;->j:Lc1/b2;

    .line 35
    .line 36
    const v2, 0x3c23d70a    # 0.01f

    .line 37
    .line 38
    .line 39
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    new-instance v6, Llx0/l;

    .line 44
    .line 45
    invoke-direct {v6, v1, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    sget-object v1, Lc1/d;->r:Lc1/b2;

    .line 49
    .line 50
    new-instance v7, Llx0/l;

    .line 51
    .line 52
    invoke-direct {v7, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    sget-object v1, Lc1/d;->n:Lc1/b2;

    .line 56
    .line 57
    new-instance v8, Llx0/l;

    .line 58
    .line 59
    invoke-direct {v8, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    sget-object v1, Lc1/d;->o:Lc1/b2;

    .line 63
    .line 64
    new-instance v9, Llx0/l;

    .line 65
    .line 66
    invoke-direct {v9, v1, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Lc1/d;->l:Lc1/b2;

    .line 70
    .line 71
    const v1, 0x3dcccccd    # 0.1f

    .line 72
    .line 73
    .line 74
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    new-instance v10, Llx0/l;

    .line 79
    .line 80
    invoke-direct {v10, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    sget-object v0, Lc1/d;->m:Lc1/b2;

    .line 84
    .line 85
    new-instance v11, Llx0/l;

    .line 86
    .line 87
    invoke-direct {v11, v0, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    filled-new-array/range {v3 .. v11}, [Llx0/l;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-static {v0}, Lmx0/x;->m([Llx0/l;)Ljava/util/Map;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    sput-object v0, Lc1/n2;->a:Ljava/lang/Object;

    .line 99
    .line 100
    return-void
.end method
