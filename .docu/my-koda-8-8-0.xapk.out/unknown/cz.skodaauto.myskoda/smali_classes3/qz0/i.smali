.class public abstract Lqz0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Luz0/m1;

.field public static final b:Luz0/m1;

.field public static final c:Luz0/a1;

.field public static final d:Luz0/a1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lqe/b;

    .line 2
    .line 3
    const/16 v1, 0x18

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqe/b;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-boolean v1, Luz0/m;->a:Z

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v2, Lc2/k;

    .line 13
    .line 14
    invoke-direct {v2, v0}, Lc2/k;-><init>(Lay0/k;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance v2, Lb81/a;

    .line 19
    .line 20
    invoke-direct {v2, v0}, Lb81/a;-><init>(Lay0/k;)V

    .line 21
    .line 22
    .line 23
    :goto_0
    sput-object v2, Lqz0/i;->a:Luz0/m1;

    .line 24
    .line 25
    new-instance v0, Lqe/b;

    .line 26
    .line 27
    const/16 v2, 0x19

    .line 28
    .line 29
    invoke-direct {v0, v2}, Lqe/b;-><init>(I)V

    .line 30
    .line 31
    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    new-instance v2, Lc2/k;

    .line 35
    .line 36
    invoke-direct {v2, v0}, Lc2/k;-><init>(Lay0/k;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance v2, Lb81/a;

    .line 41
    .line 42
    invoke-direct {v2, v0}, Lb81/a;-><init>(Lay0/k;)V

    .line 43
    .line 44
    .line 45
    :goto_1
    sput-object v2, Lqz0/i;->b:Luz0/m1;

    .line 46
    .line 47
    new-instance v0, Lqz/a;

    .line 48
    .line 49
    const/4 v2, 0x2

    .line 50
    invoke-direct {v0, v2}, Lqz/a;-><init>(I)V

    .line 51
    .line 52
    .line 53
    if-eqz v1, :cond_2

    .line 54
    .line 55
    new-instance v2, Lvp/y1;

    .line 56
    .line 57
    invoke-direct {v2, v0}, Lvp/y1;-><init>(Lay0/n;)V

    .line 58
    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    new-instance v2, Lb81/b;

    .line 62
    .line 63
    invoke-direct {v2, v0}, Lb81/b;-><init>(Lay0/n;)V

    .line 64
    .line 65
    .line 66
    :goto_2
    sput-object v2, Lqz0/i;->c:Luz0/a1;

    .line 67
    .line 68
    new-instance v0, Lqz/a;

    .line 69
    .line 70
    const/4 v2, 0x3

    .line 71
    invoke-direct {v0, v2}, Lqz/a;-><init>(I)V

    .line 72
    .line 73
    .line 74
    if-eqz v1, :cond_3

    .line 75
    .line 76
    new-instance v1, Lvp/y1;

    .line 77
    .line 78
    invoke-direct {v1, v0}, Lvp/y1;-><init>(Lay0/n;)V

    .line 79
    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_3
    new-instance v1, Lb81/b;

    .line 83
    .line 84
    invoke-direct {v1, v0}, Lb81/b;-><init>(Lay0/n;)V

    .line 85
    .line 86
    .line 87
    :goto_3
    sput-object v1, Lqz0/i;->d:Luz0/a1;

    .line 88
    .line 89
    return-void
.end method
