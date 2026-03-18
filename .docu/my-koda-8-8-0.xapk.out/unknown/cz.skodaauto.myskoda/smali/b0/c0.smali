.class public final synthetic Lb0/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/x1;


# instance fields
.field public final synthetic a:Lb0/i0;

.field public final synthetic b:Lb0/l0;


# direct methods
.method public synthetic constructor <init>(Lb0/i0;Lb0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lb0/c0;->a:Lb0/i0;

    .line 5
    .line 6
    iput-object p2, p0, Lb0/c0;->b:Lb0/l0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lh0/z1;)V
    .locals 2

    .line 1
    iget-object p1, p0, Lb0/c0;->a:Lb0/i0;

    .line 2
    .line 3
    invoke-virtual {p1}, Lb0/z1;->c()Lh0/b0;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-static {}, Llp/k1;->a()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p1, Lb0/i0;->x:Lh0/w1;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0}, Lh0/w1;->b()V

    .line 19
    .line 20
    .line 21
    iput-object v1, p1, Lb0/i0;->x:Lh0/w1;

    .line 22
    .line 23
    :cond_1
    iget-object v0, p1, Lb0/i0;->w:Lb0/u1;

    .line 24
    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    invoke-virtual {v0}, Lh0/t0;->a()V

    .line 28
    .line 29
    .line 30
    iput-object v1, p1, Lb0/i0;->w:Lb0/u1;

    .line 31
    .line 32
    :cond_2
    iget-object p0, p0, Lb0/c0;->b:Lb0/l0;

    .line 33
    .line 34
    invoke-virtual {p0}, Lb0/l0;->d()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1}, Lb0/z1;->e()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    iget-object p0, p1, Lb0/z1;->g:Lh0/o2;

    .line 41
    .line 42
    check-cast p0, Lh0/x0;

    .line 43
    .line 44
    iget-object v0, p1, Lb0/z1;->h:Lh0/k;

    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1, p0, v0}, Lb0/i0;->D(Lh0/x0;Lh0/k;)Lh0/v1;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    iput-object p0, p1, Lb0/i0;->v:Lh0/v1;

    .line 54
    .line 55
    invoke-virtual {p0}, Lh0/v1;->c()Lh0/z1;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    new-instance v0, Ljava/util/ArrayList;

    .line 64
    .line 65
    const/4 v1, 0x1

    .line 66
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 67
    .line 68
    .line 69
    const/4 v1, 0x0

    .line 70
    aget-object p0, p0, v1

    .line 71
    .line 72
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p1, p0}, Lb0/z1;->C(Ljava/util/List;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p1}, Lb0/z1;->p()V

    .line 86
    .line 87
    .line 88
    return-void
.end method
