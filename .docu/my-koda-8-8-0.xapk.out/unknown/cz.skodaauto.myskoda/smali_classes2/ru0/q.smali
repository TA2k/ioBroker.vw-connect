.class public final Lru0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lep0/b;

.field public final b:Lrt0/t;

.field public final c:Lqd0/l0;

.field public final d:Lty/g;

.field public final e:Llz/j;

.field public final f:Llb0/j;

.field public final g:Lq10/j;

.field public final h:Lk70/o0;


# direct methods
.method public constructor <init>(Lep0/b;Lrt0/t;Lqd0/l0;Lty/g;Llz/j;Llb0/j;Lq10/j;Lk70/o0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/q;->a:Lep0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/q;->b:Lrt0/t;

    .line 7
    .line 8
    iput-object p3, p0, Lru0/q;->c:Lqd0/l0;

    .line 9
    .line 10
    iput-object p4, p0, Lru0/q;->d:Lty/g;

    .line 11
    .line 12
    iput-object p5, p0, Lru0/q;->e:Llz/j;

    .line 13
    .line 14
    iput-object p6, p0, Lru0/q;->f:Llb0/j;

    .line 15
    .line 16
    iput-object p7, p0, Lru0/q;->g:Lq10/j;

    .line 17
    .line 18
    iput-object p8, p0, Lru0/q;->h:Lk70/o0;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    new-array v0, v0, [Lyy0/i;

    .line 4
    .line 5
    iget-object v1, p0, Lru0/q;->a:Lep0/b;

    .line 6
    .line 7
    invoke-virtual {v1}, Lep0/b;->invoke()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x0

    .line 12
    aput-object v1, v0, v2

    .line 13
    .line 14
    iget-object v1, p0, Lru0/q;->b:Lrt0/t;

    .line 15
    .line 16
    invoke-virtual {v1}, Lrt0/t;->invoke()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const/4 v2, 0x1

    .line 21
    aput-object v1, v0, v2

    .line 22
    .line 23
    iget-object v1, p0, Lru0/q;->c:Lqd0/l0;

    .line 24
    .line 25
    invoke-virtual {v1}, Lqd0/l0;->invoke()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    const/4 v2, 0x2

    .line 30
    aput-object v1, v0, v2

    .line 31
    .line 32
    iget-object v1, p0, Lru0/q;->d:Lty/g;

    .line 33
    .line 34
    invoke-virtual {v1}, Lty/g;->invoke()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    const/4 v2, 0x3

    .line 39
    aput-object v1, v0, v2

    .line 40
    .line 41
    iget-object v1, p0, Lru0/q;->e:Llz/j;

    .line 42
    .line 43
    invoke-virtual {v1}, Llz/j;->invoke()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    const/4 v2, 0x4

    .line 48
    aput-object v1, v0, v2

    .line 49
    .line 50
    iget-object v1, p0, Lru0/q;->f:Llb0/j;

    .line 51
    .line 52
    invoke-virtual {v1}, Llb0/j;->invoke()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const/4 v2, 0x5

    .line 57
    aput-object v1, v0, v2

    .line 58
    .line 59
    iget-object v1, p0, Lru0/q;->g:Lq10/j;

    .line 60
    .line 61
    invoke-virtual {v1}, Lq10/j;->invoke()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    const/4 v2, 0x6

    .line 66
    aput-object v1, v0, v2

    .line 67
    .line 68
    iget-object p0, p0, Lru0/q;->h:Lk70/o0;

    .line 69
    .line 70
    invoke-virtual {p0}, Lk70/o0;->invoke()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    const/4 v1, 0x7

    .line 75
    aput-object p0, v0, v1

    .line 76
    .line 77
    new-instance p0, Lib/i;

    .line 78
    .line 79
    const/4 v1, 0x2

    .line 80
    invoke-direct {p0, v0, v1}, Lib/i;-><init>([Lyy0/i;I)V

    .line 81
    .line 82
    .line 83
    return-object p0
.end method
