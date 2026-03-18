.class public final synthetic Lcl/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Lx2/s;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lcl/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lcl/a;->f:Ljava/lang/String;

    iput-object p3, p0, Lcl/a;->e:Lx2/s;

    iput p1, p0, Lcl/a;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;II)V
    .locals 0

    .line 2
    const/4 p3, 0x3

    iput p3, p0, Lcl/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcl/a;->e:Lx2/s;

    iput-object p2, p0, Lcl/a;->f:Ljava/lang/String;

    iput p4, p0, Lcl/a;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ljava/lang/String;IIB)V
    .locals 0

    .line 3
    iput p4, p0, Lcl/a;->d:I

    iput-object p1, p0, Lcl/a;->e:Lx2/s;

    iput-object p2, p0, Lcl/a;->f:Ljava/lang/String;

    iput p3, p0, Lcl/a;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lcl/a;->d:I

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
    const/4 p2, 0x1

    .line 14
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    iget-object v0, p0, Lcl/a;->e:Lx2/s;

    .line 19
    .line 20
    iget-object v1, p0, Lcl/a;->f:Ljava/lang/String;

    .line 21
    .line 22
    iget p0, p0, Lcl/a;->g:I

    .line 23
    .line 24
    invoke-static {v0, v1, p1, p2, p0}, Lxf0/y1;->c(Lx2/s;Ljava/lang/String;Ll2/o;II)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    iget p2, p0, Lcl/a;->g:I

    .line 31
    .line 32
    or-int/lit8 p2, p2, 0x1

    .line 33
    .line 34
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    iget-object v0, p0, Lcl/a;->f:Ljava/lang/String;

    .line 39
    .line 40
    iget-object p0, p0, Lcl/a;->e:Lx2/s;

    .line 41
    .line 42
    invoke-static {p2, v0, p1, p0}, Li50/s;->b(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_1
    iget p2, p0, Lcl/a;->g:I

    .line 47
    .line 48
    or-int/lit8 p2, p2, 0x1

    .line 49
    .line 50
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    iget-object v0, p0, Lcl/a;->f:Ljava/lang/String;

    .line 55
    .line 56
    iget-object p0, p0, Lcl/a;->e:Lx2/s;

    .line 57
    .line 58
    invoke-static {p2, v0, p1, p0}, Ljp/nd;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :pswitch_2
    iget p2, p0, Lcl/a;->g:I

    .line 63
    .line 64
    or-int/lit8 p2, p2, 0x1

    .line 65
    .line 66
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    iget-object v0, p0, Lcl/a;->f:Ljava/lang/String;

    .line 71
    .line 72
    iget-object p0, p0, Lcl/a;->e:Lx2/s;

    .line 73
    .line 74
    invoke-static {p2, v0, p1, p0}, Ljp/nd;->f(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
