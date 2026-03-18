.class public final synthetic Ldk/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(IIIZ)V
    .locals 0

    .line 1
    iput p3, p0, Ldk/i;->d:I

    iput-boolean p4, p0, Ldk/i;->e:Z

    iput p1, p0, Ldk/i;->f:I

    iput p2, p0, Ldk/i;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(IZI)V
    .locals 1

    .line 2
    const/4 v0, 0x3

    iput v0, p0, Ldk/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ldk/i;->f:I

    iput-boolean p2, p0, Ldk/i;->e:Z

    iput p3, p0, Ldk/i;->g:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ldk/i;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Ldk/i;->g:I

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
    iget v0, p0, Ldk/i;->f:I

    .line 22
    .line 23
    iget-boolean p0, p0, Ldk/i;->e:Z

    .line 24
    .line 25
    invoke-static {v0, p2, p1, p0}, Lxk0/e0;->d(IILl2/o;Z)V

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
    iget p2, p0, Ldk/i;->f:I

    .line 32
    .line 33
    or-int/lit8 p2, p2, 0x1

    .line 34
    .line 35
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    iget v0, p0, Ldk/i;->g:I

    .line 40
    .line 41
    iget-boolean p0, p0, Ldk/i;->e:Z

    .line 42
    .line 43
    invoke-static {p2, v0, p1, p0}, Lot0/a;->e(IILl2/o;Z)V

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :pswitch_1
    iget p2, p0, Ldk/i;->f:I

    .line 48
    .line 49
    or-int/lit8 p2, p2, 0x1

    .line 50
    .line 51
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 52
    .line 53
    .line 54
    move-result p2

    .line 55
    iget v0, p0, Ldk/i;->g:I

    .line 56
    .line 57
    iget-boolean p0, p0, Ldk/i;->e:Z

    .line 58
    .line 59
    invoke-static {p2, v0, p1, p0}, Lfc/a;->a(IILl2/o;Z)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_2
    iget p2, p0, Ldk/i;->f:I

    .line 64
    .line 65
    or-int/lit8 p2, p2, 0x1

    .line 66
    .line 67
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    iget v0, p0, Ldk/i;->g:I

    .line 72
    .line 73
    iget-boolean p0, p0, Ldk/i;->e:Z

    .line 74
    .line 75
    invoke-static {p2, v0, p1, p0}, Ldk/b;->e(IILl2/o;Z)V

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
