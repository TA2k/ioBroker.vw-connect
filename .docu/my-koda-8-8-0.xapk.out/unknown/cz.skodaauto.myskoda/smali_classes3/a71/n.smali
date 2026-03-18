.class public final synthetic La71/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(IIZ)V
    .locals 0

    .line 1
    iput p2, p0, La71/n;->d:I

    iput-boolean p3, p0, La71/n;->e:Z

    iput p1, p0, La71/n;->f:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, La71/n;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p2, p0, La71/n;->e:Z

    iput p1, p0, La71/n;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La71/n;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget p2, p0, La71/n;->f:I

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
    iget-boolean p0, p0, La71/n;->e:Z

    .line 22
    .line 23
    invoke-static {p0, p1, p2}, Lik/a;->e(ZLl2/o;I)V

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    iget p2, p0, La71/n;->f:I

    .line 33
    .line 34
    or-int/lit8 p2, p2, 0x1

    .line 35
    .line 36
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 41
    .line 42
    iget-boolean p0, p0, La71/n;->e:Z

    .line 43
    .line 44
    invoke-static {p2, p1, v0, p0}, Ldt0/a;->c(ILl2/o;Lx2/s;Z)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 49
    .line 50
    .line 51
    iget p2, p0, La71/n;->f:I

    .line 52
    .line 53
    or-int/lit8 p2, p2, 0x1

    .line 54
    .line 55
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 56
    .line 57
    .line 58
    move-result p2

    .line 59
    iget-boolean p0, p0, La71/n;->e:Z

    .line 60
    .line 61
    invoke-static {p0, p1, p2}, La71/b;->f(ZLl2/o;I)V

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
