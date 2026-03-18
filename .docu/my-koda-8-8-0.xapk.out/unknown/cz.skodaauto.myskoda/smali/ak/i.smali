.class public final synthetic Lak/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;II)V
    .locals 0

    .line 1
    iput p4, p0, Lak/i;->d:I

    iput p1, p0, Lak/i;->f:I

    iput-object p2, p0, Lak/i;->e:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lak/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lak/i;->e:Ljava/lang/String;

    iput p2, p0, Lak/i;->f:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;II)V
    .locals 0

    .line 3
    const/4 p2, 0x1

    iput p2, p0, Lak/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lak/i;->e:Ljava/lang/String;

    iput p3, p0, Lak/i;->f:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lak/i;->d:I

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
    const/16 p2, 0x31

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget v0, p0, Lak/i;->f:I

    .line 20
    .line 21
    iget-object p0, p0, Lak/i;->e:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, p2, p0, p1}, Lyj/a;->g(IILjava/lang/String;Ll2/o;)V

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
    const/16 p2, 0x31

    .line 30
    .line 31
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    iget v0, p0, Lak/i;->f:I

    .line 36
    .line 37
    iget-object p0, p0, Lak/i;->e:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v0, p2, p0, p1}, Llk/a;->i(IILjava/lang/String;Ll2/o;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    const/4 p2, 0x1

    .line 44
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 45
    .line 46
    .line 47
    move-result p2

    .line 48
    iget v0, p0, Lak/i;->f:I

    .line 49
    .line 50
    iget-object p0, p0, Lak/i;->e:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {p2, v0, p0, p1}, Leh/a;->a(IILjava/lang/String;Ll2/o;)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :pswitch_2
    iget p2, p0, Lak/i;->f:I

    .line 57
    .line 58
    or-int/lit8 p2, p2, 0x1

    .line 59
    .line 60
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    iget-object p0, p0, Lak/i;->e:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {p0, p1, p2}, Lak/a;->k(Ljava/lang/String;Ll2/o;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    nop

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
