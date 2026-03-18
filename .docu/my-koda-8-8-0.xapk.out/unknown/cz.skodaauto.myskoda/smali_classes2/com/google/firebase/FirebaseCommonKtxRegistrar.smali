.class public final Lcom/google/firebase/FirebaseCommonKtxRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0007\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0019\u0010\u0006\u001a\u000c\u0012\u0008\u0012\u0006\u0012\u0002\u0008\u00030\u00050\u0004H\u0016\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Lcom/google/firebase/FirebaseCommonKtxRegistrar;",
        "Lcom/google/firebase/components/ComponentRegistrar;",
        "<init>",
        "()V",
        "",
        "Lgs/b;",
        "getComponents",
        "()Ljava/util/List;",
        "com.google.firebase-firebase-common"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lyr/a;

    .line 4
    .line 5
    const-class v1, Lvy0/x;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Lgs/b;->a(Lgs/s;)Lgs/a;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    new-instance v2, Lgs/s;

    .line 15
    .line 16
    const-class v3, Ljava/util/concurrent/Executor;

    .line 17
    .line 18
    invoke-direct {v2, v0, v3}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 19
    .line 20
    .line 21
    new-instance v0, Lgs/k;

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    const/4 v5, 0x0

    .line 25
    invoke-direct {v0, v2, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lgs/a;->a(Lgs/k;)V

    .line 29
    .line 30
    .line 31
    sget-object v0, Lsr/g;->e:Lsr/g;

    .line 32
    .line 33
    iput-object v0, p0, Lgs/a;->f:Lgs/e;

    .line 34
    .line 35
    invoke-virtual {p0}, Lgs/a;->b()Lgs/b;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    new-instance v0, Lgs/s;

    .line 40
    .line 41
    const-class v2, Lyr/c;

    .line 42
    .line 43
    invoke-direct {v0, v2, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0}, Lgs/b;->a(Lgs/s;)Lgs/a;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    new-instance v6, Lgs/s;

    .line 51
    .line 52
    invoke-direct {v6, v2, v3}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 53
    .line 54
    .line 55
    new-instance v2, Lgs/k;

    .line 56
    .line 57
    invoke-direct {v2, v6, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 61
    .line 62
    .line 63
    sget-object v2, Lsr/g;->f:Lsr/g;

    .line 64
    .line 65
    iput-object v2, v0, Lgs/a;->f:Lgs/e;

    .line 66
    .line 67
    invoke-virtual {v0}, Lgs/a;->b()Lgs/b;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    new-instance v2, Lgs/s;

    .line 72
    .line 73
    const-class v6, Lyr/b;

    .line 74
    .line 75
    invoke-direct {v2, v6, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 76
    .line 77
    .line 78
    invoke-static {v2}, Lgs/b;->a(Lgs/s;)Lgs/a;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    new-instance v7, Lgs/s;

    .line 83
    .line 84
    invoke-direct {v7, v6, v3}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 85
    .line 86
    .line 87
    new-instance v6, Lgs/k;

    .line 88
    .line 89
    invoke-direct {v6, v7, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2, v6}, Lgs/a;->a(Lgs/k;)V

    .line 93
    .line 94
    .line 95
    sget-object v6, Lsr/g;->g:Lsr/g;

    .line 96
    .line 97
    iput-object v6, v2, Lgs/a;->f:Lgs/e;

    .line 98
    .line 99
    invoke-virtual {v2}, Lgs/a;->b()Lgs/b;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    new-instance v6, Lgs/s;

    .line 104
    .line 105
    const-class v7, Lyr/d;

    .line 106
    .line 107
    invoke-direct {v6, v7, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 108
    .line 109
    .line 110
    invoke-static {v6}, Lgs/b;->a(Lgs/s;)Lgs/a;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    new-instance v6, Lgs/s;

    .line 115
    .line 116
    invoke-direct {v6, v7, v3}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 117
    .line 118
    .line 119
    new-instance v3, Lgs/k;

    .line 120
    .line 121
    invoke-direct {v3, v6, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1, v3}, Lgs/a;->a(Lgs/k;)V

    .line 125
    .line 126
    .line 127
    sget-object v3, Lsr/g;->h:Lsr/g;

    .line 128
    .line 129
    iput-object v3, v1, Lgs/a;->f:Lgs/e;

    .line 130
    .line 131
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    filled-new-array {p0, v0, v2, v1}, [Lgs/b;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0
.end method
