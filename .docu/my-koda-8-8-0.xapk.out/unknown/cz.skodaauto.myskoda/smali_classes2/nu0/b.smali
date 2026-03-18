.class public final synthetic Lnu0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Lt2/b;I)V
    .locals 0

    .line 1
    const/4 p3, 0x0

    iput p3, p0, Lnu0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnu0/b;->f:Ljava/util/List;

    iput-object p2, p0, Lnu0/b;->e:Lt2/b;

    return-void
.end method

.method public synthetic constructor <init>(Lt2/b;Ljava/util/List;I)V
    .locals 0

    .line 2
    const/4 p3, 0x1

    iput p3, p0, Lnu0/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnu0/b;->e:Lt2/b;

    iput-object p2, p0, Lnu0/b;->f:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnu0/b;->d:I

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
    const/16 p2, 0x187

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Lnu0/b;->f:Ljava/util/List;

    .line 20
    .line 21
    iget-object p0, p0, Lnu0/b;->e:Lt2/b;

    .line 22
    .line 23
    invoke-static {p2, v0, p1, p0}, Lzb/o0;->a(ILjava/util/List;Ll2/o;Lt2/b;)V

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
    iget-object v0, p0, Lnu0/b;->f:Ljava/util/List;

    .line 36
    .line 37
    iget-object p0, p0, Lnu0/b;->e:Lt2/b;

    .line 38
    .line 39
    invoke-static {p2, v0, p1, p0}, Ljp/wa;->e(ILjava/util/List;Ll2/o;Lt2/b;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
