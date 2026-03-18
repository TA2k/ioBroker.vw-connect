.class public final synthetic Li40/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/c2;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/c2;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/m1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/m1;->e:Lh40/c2;

    iput-object p2, p0, Li40/m1;->f:Lay0/k;

    iput-object p3, p0, Li40/m1;->g:Lay0/k;

    iput-object p4, p0, Li40/m1;->h:Lay0/k;

    iput-object p5, p0, Li40/m1;->i:Lay0/a;

    iput-object p6, p0, Li40/m1;->j:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/c2;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p7, 0x0

    iput p7, p0, Li40/m1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/m1;->e:Lh40/c2;

    iput-object p2, p0, Li40/m1;->f:Lay0/k;

    iput-object p3, p0, Li40/m1;->g:Lay0/k;

    iput-object p4, p0, Li40/m1;->h:Lay0/k;

    iput-object p5, p0, Li40/m1;->i:Lay0/a;

    iput-object p6, p0, Li40/m1;->j:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li40/m1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    move-object v7, p1

    .line 25
    check-cast v7, Ll2/t;

    .line 26
    .line 27
    invoke-virtual {v7, p2, v0}, Ll2/t;->O(IZ)Z

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    if-eqz p1, :cond_1

    .line 32
    .line 33
    const/4 v8, 0x0

    .line 34
    iget-object v1, p0, Li40/m1;->e:Lh40/c2;

    .line 35
    .line 36
    iget-object v2, p0, Li40/m1;->f:Lay0/k;

    .line 37
    .line 38
    iget-object v3, p0, Li40/m1;->g:Lay0/k;

    .line 39
    .line 40
    iget-object v4, p0, Li40/m1;->h:Lay0/k;

    .line 41
    .line 42
    iget-object v5, p0, Li40/m1;->i:Lay0/a;

    .line 43
    .line 44
    iget-object v6, p0, Li40/m1;->j:Lay0/a;

    .line 45
    .line 46
    invoke-static/range {v1 .. v8}, Li40/p1;->a(Lh40/c2;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_0
    move-object v6, p1

    .line 57
    check-cast v6, Ll2/o;

    .line 58
    .line 59
    check-cast p2, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    const/4 p1, 0x1

    .line 65
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    iget-object v0, p0, Li40/m1;->e:Lh40/c2;

    .line 70
    .line 71
    iget-object v1, p0, Li40/m1;->f:Lay0/k;

    .line 72
    .line 73
    iget-object v2, p0, Li40/m1;->g:Lay0/k;

    .line 74
    .line 75
    iget-object v3, p0, Li40/m1;->h:Lay0/k;

    .line 76
    .line 77
    iget-object v4, p0, Li40/m1;->i:Lay0/a;

    .line 78
    .line 79
    iget-object v5, p0, Li40/m1;->j:Lay0/a;

    .line 80
    .line 81
    invoke-static/range {v0 .. v7}, Li40/p1;->a(Lh40/c2;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 82
    .line 83
    .line 84
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    return-object p0

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
