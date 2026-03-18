.class public final synthetic Li40/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/g1;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh40/g1;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;II)V
    .locals 0

    .line 1
    iput p8, p0, Li40/y0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/y0;->e:Lh40/g1;

    .line 4
    .line 5
    iput-object p2, p0, Li40/y0;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Li40/y0;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Li40/y0;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Li40/y0;->i:Lay0/k;

    .line 12
    .line 13
    iput-object p6, p0, Li40/y0;->j:Lay0/a;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Li40/y0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v7, p1

    .line 7
    check-cast v7, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result v8

    .line 19
    iget-object v1, p0, Li40/y0;->e:Lh40/g1;

    .line 20
    .line 21
    iget-object v2, p0, Li40/y0;->f:Lay0/a;

    .line 22
    .line 23
    iget-object v3, p0, Li40/y0;->g:Lay0/a;

    .line 24
    .line 25
    iget-object v4, p0, Li40/y0;->h:Lay0/a;

    .line 26
    .line 27
    iget-object v5, p0, Li40/y0;->i:Lay0/k;

    .line 28
    .line 29
    iget-object v6, p0, Li40/y0;->j:Lay0/a;

    .line 30
    .line 31
    invoke-static/range {v1 .. v8}, Li40/z0;->c(Lh40/g1;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_0
    move-object v6, p1

    .line 38
    check-cast v6, Ll2/o;

    .line 39
    .line 40
    check-cast p2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    const/4 p1, 0x1

    .line 46
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v7

    .line 50
    iget-object v0, p0, Li40/y0;->e:Lh40/g1;

    .line 51
    .line 52
    iget-object v1, p0, Li40/y0;->f:Lay0/a;

    .line 53
    .line 54
    iget-object v2, p0, Li40/y0;->g:Lay0/a;

    .line 55
    .line 56
    iget-object v3, p0, Li40/y0;->h:Lay0/a;

    .line 57
    .line 58
    iget-object v4, p0, Li40/y0;->i:Lay0/k;

    .line 59
    .line 60
    iget-object v5, p0, Li40/y0;->j:Lay0/a;

    .line 61
    .line 62
    invoke-static/range {v0 .. v7}, Li40/z0;->c(Lh40/g1;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    nop

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
