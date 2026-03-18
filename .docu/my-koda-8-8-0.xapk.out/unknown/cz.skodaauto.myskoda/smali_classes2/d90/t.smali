.class public final synthetic Ld90/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lt2/b;II)V
    .locals 0

    .line 1
    iput p4, p0, Ld90/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld90/t;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Ld90/t;->f:Lt2/b;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ld90/t;->d:I

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
    iget-object v0, p0, Ld90/t;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object p0, p0, Ld90/t;->f:Lt2/b;

    .line 22
    .line 23
    invoke-static {v0, p0, p1, p2}, Ljp/f1;->a(Ljava/lang/String;Lt2/b;Ll2/o;I)V

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
    iget-object v0, p0, Ld90/t;->e:Ljava/lang/String;

    .line 36
    .line 37
    iget-object p0, p0, Ld90/t;->f:Lt2/b;

    .line 38
    .line 39
    invoke-static {v0, p0, p1, p2}, Lz70/s;->j(Ljava/lang/String;Lt2/b;Ll2/o;I)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    const/16 p2, 0x31

    .line 44
    .line 45
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    iget-object v0, p0, Ld90/t;->e:Ljava/lang/String;

    .line 50
    .line 51
    iget-object p0, p0, Ld90/t;->f:Lt2/b;

    .line 52
    .line 53
    invoke-static {v0, p0, p1, p2}, Ljp/nf;->b(Ljava/lang/String;Lt2/b;Ll2/o;I)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :pswitch_2
    const/16 p2, 0x31

    .line 58
    .line 59
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    iget-object v0, p0, Ld90/t;->e:Ljava/lang/String;

    .line 64
    .line 65
    iget-object p0, p0, Ld90/t;->f:Lt2/b;

    .line 66
    .line 67
    invoke-static {v0, p0, p1, p2}, Ld90/v;->b(Ljava/lang/String;Lt2/b;Ll2/o;I)V

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
