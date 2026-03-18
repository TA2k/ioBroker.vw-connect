.class public final synthetic Lnd0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lay0/k;I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lnd0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnd0/a;->e:Lay0/k;

    iput-object p2, p0, Lnd0/a;->f:Lay0/k;

    iput p3, p0, Lnd0/a;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/k;II)V
    .locals 0

    .line 2
    const/4 p3, 0x0

    iput p3, p0, Lnd0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnd0/a;->e:Lay0/k;

    iput-object p2, p0, Lnd0/a;->f:Lay0/k;

    iput p4, p0, Lnd0/a;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lnd0/a;->d:I

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
    iget p2, p0, Lnd0/a;->g:I

    .line 14
    .line 15
    or-int/lit8 p2, p2, 0x1

    .line 16
    .line 17
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    iget-object v0, p0, Lnd0/a;->e:Lay0/k;

    .line 22
    .line 23
    iget-object p0, p0, Lnd0/a;->f:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lxk0/d0;->a(Lay0/k;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    move-object v4, p1

    .line 32
    check-cast v4, Ll2/o;

    .line 33
    .line 34
    check-cast p2, Ljava/lang/Integer;

    .line 35
    .line 36
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    const/4 p1, 0x1

    .line 40
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget v1, p0, Lnd0/a;->g:I

    .line 45
    .line 46
    iget-object v2, p0, Lnd0/a;->e:Lay0/k;

    .line 47
    .line 48
    iget-object v3, p0, Lnd0/a;->f:Lay0/k;

    .line 49
    .line 50
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 51
    .line 52
    invoke-static/range {v0 .. v5}, Ljp/ka;->b(IILay0/k;Lay0/k;Ll2/o;Lx2/s;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
