.class public final synthetic Lxk0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lwk0/x1;

.field public final synthetic f:Li91/s2;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Li91/s2;Lwk0/x1;I)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lxk0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxk0/c;->f:Li91/s2;

    iput-object p2, p0, Lxk0/c;->e:Lwk0/x1;

    iput p3, p0, Lxk0/c;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lwk0/x1;Li91/s2;II)V
    .locals 0

    .line 2
    iput p4, p0, Lxk0/c;->d:I

    iput-object p1, p0, Lxk0/c;->e:Lwk0/x1;

    iput-object p2, p0, Lxk0/c;->f:Li91/s2;

    iput p3, p0, Lxk0/c;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lxk0/c;->d:I

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 11
    .line 12
    .line 13
    iget p2, p0, Lxk0/c;->g:I

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
    iget-object v0, p0, Lxk0/c;->f:Li91/s2;

    .line 22
    .line 23
    iget-object p0, p0, Lxk0/c;->e:Lwk0/x1;

    .line 24
    .line 25
    invoke-static {p2, v0, p1, p0}, Lxk0/h;->r0(ILi91/s2;Ll2/o;Lwk0/x1;)V

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
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget p2, p0, Lxk0/c;->g:I

    .line 35
    .line 36
    or-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    iget-object v0, p0, Lxk0/c;->f:Li91/s2;

    .line 43
    .line 44
    iget-object p0, p0, Lxk0/c;->e:Lwk0/x1;

    .line 45
    .line 46
    invoke-static {p2, v0, p1, p0}, Lxk0/h;->w(ILi91/s2;Ll2/o;Lwk0/x1;)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 51
    .line 52
    .line 53
    iget p2, p0, Lxk0/c;->g:I

    .line 54
    .line 55
    or-int/lit8 p2, p2, 0x1

    .line 56
    .line 57
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 58
    .line 59
    .line 60
    move-result p2

    .line 61
    iget-object v0, p0, Lxk0/c;->f:Li91/s2;

    .line 62
    .line 63
    iget-object p0, p0, Lxk0/c;->e:Lwk0/x1;

    .line 64
    .line 65
    invoke-static {p2, v0, p1, p0}, Lxk0/h;->b(ILi91/s2;Ll2/o;Lwk0/x1;)V

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 70
    .line 71
    .line 72
    iget p2, p0, Lxk0/c;->g:I

    .line 73
    .line 74
    or-int/lit8 p2, p2, 0x1

    .line 75
    .line 76
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    iget-object v0, p0, Lxk0/c;->f:Li91/s2;

    .line 81
    .line 82
    iget-object p0, p0, Lxk0/c;->e:Lwk0/x1;

    .line 83
    .line 84
    invoke-static {p2, v0, p1, p0}, Lxk0/d;->d(ILi91/s2;Ll2/o;Lwk0/x1;)V

    .line 85
    .line 86
    .line 87
    goto :goto_0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
