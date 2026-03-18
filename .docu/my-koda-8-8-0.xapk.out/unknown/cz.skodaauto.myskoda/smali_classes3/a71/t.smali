.class public final synthetic La71/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;


# direct methods
.method public synthetic constructor <init>(ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, La71/t;->d:Z

    .line 5
    .line 6
    iput-boolean p2, p0, La71/t;->e:Z

    .line 7
    .line 8
    iput-object p3, p0, La71/t;->f:Lay0/a;

    .line 9
    .line 10
    iput-object p4, p0, La71/t;->g:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, La71/t;->h:Lay0/a;

    .line 13
    .line 14
    iput-object p6, p0, La71/t;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, La71/t;->j:Lay0/a;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Lk1/q;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p3

    .line 11
    const-string v0, "$this$FuSiScaffold"

    .line 12
    .line 13
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    and-int/lit8 p1, p3, 0x11

    .line 17
    .line 18
    const/16 v0, 0x10

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    if-eq p1, v0, :cond_0

    .line 22
    .line 23
    move p1, v1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p1, 0x0

    .line 26
    :goto_0
    and-int/2addr p3, v1

    .line 27
    move-object v8, p2

    .line 28
    check-cast v8, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {v8, p3, p1}, Ll2/t;->O(IZ)Z

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-eqz p1, :cond_1

    .line 35
    .line 36
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 37
    .line 38
    const/high16 p2, 0x3f800000    # 1.0f

    .line 39
    .line 40
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    const/4 v9, 0x6

    .line 45
    iget-boolean v1, p0, La71/t;->d:Z

    .line 46
    .line 47
    iget-boolean v2, p0, La71/t;->e:Z

    .line 48
    .line 49
    iget-object v3, p0, La71/t;->f:Lay0/a;

    .line 50
    .line 51
    iget-object v4, p0, La71/t;->g:Lay0/a;

    .line 52
    .line 53
    iget-object v5, p0, La71/t;->h:Lay0/a;

    .line 54
    .line 55
    iget-object v6, p0, La71/t;->i:Lay0/a;

    .line 56
    .line 57
    iget-object v7, p0, La71/t;->j:Lay0/a;

    .line 58
    .line 59
    invoke-static/range {v0 .. v9}, La71/b;->i(Lx2/s;ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 64
    .line 65
    .line 66
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0
.end method
