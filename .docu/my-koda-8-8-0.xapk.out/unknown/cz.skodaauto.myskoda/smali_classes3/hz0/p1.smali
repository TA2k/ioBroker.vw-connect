.class public abstract Lhz0/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljz0/u;

.field public static final b:Ljz0/u;

.field public static final c:Ljz0/u;

.field public static final d:Ljz0/l;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Ljz0/u;

    .line 2
    .line 3
    new-instance v1, Ljz0/r;

    .line 4
    .line 5
    sget-object v2, Lhz0/l1;->d:Lhz0/l1;

    .line 6
    .line 7
    invoke-interface {v2}, Lhy0/c;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-direct {v1, v2, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    const/16 v5, 0x38

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    const/16 v3, 0x17

    .line 19
    .line 20
    invoke-direct/range {v0 .. v5}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Lhz0/p1;->a:Ljz0/u;

    .line 24
    .line 25
    new-instance v1, Ljz0/u;

    .line 26
    .line 27
    new-instance v2, Ljz0/r;

    .line 28
    .line 29
    sget-object v0, Lhz0/n1;->d:Lhz0/n1;

    .line 30
    .line 31
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-direct {v2, v0, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    const/16 v6, 0x38

    .line 40
    .line 41
    const/4 v3, 0x0

    .line 42
    const/16 v4, 0x3b

    .line 43
    .line 44
    invoke-direct/range {v1 .. v6}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 45
    .line 46
    .line 47
    sput-object v1, Lhz0/p1;->b:Ljz0/u;

    .line 48
    .line 49
    new-instance v2, Ljz0/u;

    .line 50
    .line 51
    new-instance v3, Ljz0/r;

    .line 52
    .line 53
    sget-object v0, Lhz0/o1;->d:Lhz0/o1;

    .line 54
    .line 55
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-direct {v3, v0, v1}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    const/4 v6, 0x0

    .line 63
    const/16 v7, 0x28

    .line 64
    .line 65
    const/4 v4, 0x0

    .line 66
    const/16 v5, 0x3b

    .line 67
    .line 68
    invoke-direct/range {v2 .. v7}, Ljz0/u;-><init>(Ljz0/r;IILhz0/d1;I)V

    .line 69
    .line 70
    .line 71
    sput-object v2, Lhz0/p1;->c:Ljz0/u;

    .line 72
    .line 73
    new-instance v0, Ljz0/l;

    .line 74
    .line 75
    new-instance v1, Ljz0/r;

    .line 76
    .line 77
    sget-object v2, Lhz0/k1;->d:Lhz0/k1;

    .line 78
    .line 79
    const-string v3, "nanosecond"

    .line 80
    .line 81
    invoke-direct {v1, v2, v3}, Ljz0/r;-><init>(Lhy0/l;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    new-instance v2, Liz0/a;

    .line 85
    .line 86
    const/16 v3, 0x9

    .line 87
    .line 88
    invoke-direct {v2, v4, v3}, Liz0/a;-><init>(II)V

    .line 89
    .line 90
    .line 91
    const/16 v3, 0xa

    .line 92
    .line 93
    invoke-direct {v0, v1, v2, v3}, Ljz0/l;-><init>(Ljz0/r;Liz0/a;I)V

    .line 94
    .line 95
    .line 96
    sput-object v0, Lhz0/p1;->d:Ljz0/l;

    .line 97
    .line 98
    sget-object v0, Lhz0/j1;->d:Lhz0/j1;

    .line 99
    .line 100
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    const-string v1, "name"

    .line 105
    .line 106
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    sget-object v0, Lhz0/m1;->d:Lhz0/m1;

    .line 110
    .line 111
    invoke-interface {v0}, Lhy0/c;->getName()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v0

    .line 115
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    return-void
.end method
