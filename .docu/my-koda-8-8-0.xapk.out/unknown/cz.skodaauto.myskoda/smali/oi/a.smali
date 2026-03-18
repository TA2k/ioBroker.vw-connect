.class public final synthetic Loi/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Lt2/b;II)V
    .locals 0

    .line 1
    iput p3, p0, Loi/a;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    sget-object p3, Loi/b;->d:Loi/b;

    .line 7
    .line 8
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Loi/a;->e:Lt2/b;

    .line 12
    .line 13
    iput p2, p0, Loi/a;->f:I

    .line 14
    .line 15
    return-void

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Loi/a;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    iget v2, p0, Loi/a;->f:I

    .line 6
    .line 7
    iget-object p0, p0, Loi/a;->e:Lt2/b;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    check-cast p1, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    or-int/lit8 p2, v2, 0x1

    .line 20
    .line 21
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    invoke-static {p0, p1, p2}, Lzb/b;->l(Lt2/b;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    return-object v1

    .line 29
    :pswitch_0
    sget-object v0, Loi/b;->d:Loi/b;

    .line 30
    .line 31
    check-cast p1, Ll2/o;

    .line 32
    .line 33
    check-cast p2, Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    or-int/lit8 p2, v2, 0x1

    .line 39
    .line 40
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    invoke-static {p0, p1, p2}, Ljp/vb;->a(Lt2/b;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    return-object v1

    .line 48
    :pswitch_1
    sget-object v0, Loi/b;->d:Loi/b;

    .line 49
    .line 50
    check-cast p1, Ll2/o;

    .line 51
    .line 52
    check-cast p2, Ljava/lang/Integer;

    .line 53
    .line 54
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    or-int/lit8 p2, v2, 0x1

    .line 58
    .line 59
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    invoke-static {p0, p1, p2}, Ljp/vb;->a(Lt2/b;Ll2/o;I)V

    .line 64
    .line 65
    .line 66
    return-object v1

    .line 67
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
