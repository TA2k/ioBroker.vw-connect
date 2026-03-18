.class public final Lj7/f;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ly6/q;

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:I

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ly6/q;Lj7/g;III)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lj7/f;->f:I

    .line 1
    iput-object p1, p0, Lj7/f;->k:Ljava/lang/Object;

    iput-object p2, p0, Lj7/f;->g:Ly6/q;

    iput-object p3, p0, Lj7/f;->l:Ljava/lang/Object;

    iput p4, p0, Lj7/f;->h:I

    iput p5, p0, Lj7/f;->i:I

    iput p6, p0, Lj7/f;->j:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Ly6/s;Ly6/q;ILy6/g;II)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lj7/f;->f:I

    .line 2
    iput-object p1, p0, Lj7/f;->k:Ljava/lang/Object;

    iput-object p2, p0, Lj7/f;->g:Ly6/q;

    iput p3, p0, Lj7/f;->h:I

    iput-object p4, p0, Lj7/f;->l:Ljava/lang/Object;

    iput p5, p0, Lj7/f;->i:I

    iput p6, p0, Lj7/f;->j:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lj7/f;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lj7/f;->k:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v1, p1

    .line 17
    check-cast v1, Ly6/s;

    .line 18
    .line 19
    iget-object p1, p0, Lj7/f;->l:Ljava/lang/Object;

    .line 20
    .line 21
    move-object v4, p1

    .line 22
    check-cast v4, Ly6/g;

    .line 23
    .line 24
    iget p1, p0, Lj7/f;->i:I

    .line 25
    .line 26
    or-int/lit8 v6, p1, 0x1

    .line 27
    .line 28
    iget v7, p0, Lj7/f;->j:I

    .line 29
    .line 30
    iget-object v2, p0, Lj7/f;->g:Ly6/q;

    .line 31
    .line 32
    iget v3, p0, Lj7/f;->h:I

    .line 33
    .line 34
    invoke-static/range {v1 .. v7}, Llp/ag;->a(Ly6/s;Ly6/q;ILy6/g;Ll2/o;II)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    move-object v4, p1

    .line 41
    check-cast v4, Ll2/o;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Number;

    .line 44
    .line 45
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 46
    .line 47
    .line 48
    iget-object p1, p0, Lj7/f;->k:Ljava/lang/Object;

    .line 49
    .line 50
    move-object v0, p1

    .line 51
    check-cast v0, Ljava/lang/String;

    .line 52
    .line 53
    iget-object p1, p0, Lj7/f;->l:Ljava/lang/Object;

    .line 54
    .line 55
    move-object v2, p1

    .line 56
    check-cast v2, Lj7/g;

    .line 57
    .line 58
    iget p1, p0, Lj7/f;->i:I

    .line 59
    .line 60
    or-int/lit8 v5, p1, 0x1

    .line 61
    .line 62
    iget v6, p0, Lj7/f;->j:I

    .line 63
    .line 64
    iget-object v1, p0, Lj7/f;->g:Ly6/q;

    .line 65
    .line 66
    iget v3, p0, Lj7/f;->h:I

    .line 67
    .line 68
    invoke-static/range {v0 .. v6}, Llp/mb;->a(Ljava/lang/String;Ly6/q;Lj7/g;ILl2/o;II)V

    .line 69
    .line 70
    .line 71
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
