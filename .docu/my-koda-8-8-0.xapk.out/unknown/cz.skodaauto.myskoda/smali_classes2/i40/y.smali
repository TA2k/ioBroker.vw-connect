.class public final synthetic Li40/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/k0;

.field public final synthetic f:Ljava/util/List;

.field public final synthetic g:Lay0/k;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lx2/s;


# direct methods
.method public synthetic constructor <init>(Lh40/k0;Ljava/util/List;Lay0/k;Lay0/a;Lay0/a;Lx2/s;II)V
    .locals 0

    .line 1
    iput p8, p0, Li40/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/y;->e:Lh40/k0;

    .line 4
    .line 5
    iput-object p2, p0, Li40/y;->f:Ljava/util/List;

    .line 6
    .line 7
    iput-object p3, p0, Li40/y;->g:Lay0/k;

    .line 8
    .line 9
    iput-object p4, p0, Li40/y;->h:Lay0/a;

    .line 10
    .line 11
    iput-object p5, p0, Li40/y;->i:Lay0/a;

    .line 12
    .line 13
    iput-object p6, p0, Li40/y;->j:Lx2/s;

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
    iget v0, p0, Li40/y;->d:I

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
    const p1, 0x30001

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result v8

    .line 21
    iget-object v1, p0, Li40/y;->e:Lh40/k0;

    .line 22
    .line 23
    iget-object v2, p0, Li40/y;->f:Ljava/util/List;

    .line 24
    .line 25
    iget-object v3, p0, Li40/y;->g:Lay0/k;

    .line 26
    .line 27
    iget-object v4, p0, Li40/y;->h:Lay0/a;

    .line 28
    .line 29
    iget-object v5, p0, Li40/y;->i:Lay0/a;

    .line 30
    .line 31
    iget-object v6, p0, Li40/y;->j:Lx2/s;

    .line 32
    .line 33
    invoke-static/range {v1 .. v8}, Li40/e0;->a(Lh40/k0;Ljava/util/List;Lay0/k;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    move-object v6, p1

    .line 40
    check-cast v6, Ll2/o;

    .line 41
    .line 42
    check-cast p2, Ljava/lang/Integer;

    .line 43
    .line 44
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    const p1, 0x30001

    .line 48
    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    iget-object v0, p0, Li40/y;->e:Lh40/k0;

    .line 55
    .line 56
    iget-object v1, p0, Li40/y;->f:Ljava/util/List;

    .line 57
    .line 58
    iget-object v2, p0, Li40/y;->g:Lay0/k;

    .line 59
    .line 60
    iget-object v3, p0, Li40/y;->h:Lay0/a;

    .line 61
    .line 62
    iget-object v4, p0, Li40/y;->i:Lay0/a;

    .line 63
    .line 64
    iget-object v5, p0, Li40/y;->j:Lx2/s;

    .line 65
    .line 66
    invoke-static/range {v0 .. v7}, Li40/e0;->a(Lh40/k0;Ljava/util/List;Lay0/k;Lay0/a;Lay0/a;Lx2/s;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
