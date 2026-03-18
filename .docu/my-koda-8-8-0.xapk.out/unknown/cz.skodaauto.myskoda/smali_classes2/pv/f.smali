.class public final Lpv/f;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lfv/f;


# direct methods
.method public constructor <init>(Lfv/f;)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lpv/f;->f:Lfv/f;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final t(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lov/f;

    .line 2
    .line 3
    check-cast p1, Lqv/a;

    .line 4
    .line 5
    invoke-virtual {p1}, Lqv/a;->b()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Llp/ng;->c(Ljava/lang/String;)Llp/lg;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Lpv/a;

    .line 14
    .line 15
    iget-object p0, p0, Lpv/f;->f:Lfv/f;

    .line 16
    .line 17
    invoke-virtual {p0}, Lfv/f;->b()Landroid/content/Context;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object v2, Ljo/f;->b:Ljo/f;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-static {p0}, Ljo/f;->a(Landroid/content/Context;)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    const v3, 0xc337960

    .line 31
    .line 32
    .line 33
    if-ge v2, v3, :cond_1

    .line 34
    .line 35
    invoke-virtual {p1}, Lqv/a;->a()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance v2, La8/b;

    .line 43
    .line 44
    invoke-direct {v2, p0}, La8/b;-><init>(Landroid/content/Context;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    :goto_0
    new-instance v2, La8/l;

    .line 49
    .line 50
    invoke-direct {v2, p0, p1, v0}, La8/l;-><init>(Landroid/content/Context;Lqv/a;Llp/lg;)V

    .line 51
    .line 52
    .line 53
    :goto_1
    invoke-direct {v1, v0, v2, p1}, Lpv/a;-><init>(Llp/lg;Lpv/c;Lqv/a;)V

    .line 54
    .line 55
    .line 56
    return-object v1
.end method
