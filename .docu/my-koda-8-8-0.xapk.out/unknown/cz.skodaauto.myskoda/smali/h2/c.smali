.class public final synthetic Lh2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:F

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FFLt2/b;I)V
    .locals 0

    .line 1
    const/4 p4, 0x0

    iput p4, p0, Lh2/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lh2/c;->e:F

    iput p2, p0, Lh2/c;->f:F

    iput-object p3, p0, Lh2/c;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;FFI)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Lh2/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/c;->g:Ljava/lang/Object;

    iput p2, p0, Lh2/c;->e:F

    iput p3, p0, Lh2/c;->f:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lh2/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/c;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/List;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/16 p2, 0x31

    .line 18
    .line 19
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    iget v1, p0, Lh2/c;->e:F

    .line 24
    .line 25
    iget p0, p0, Lh2/c;->f:F

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1, p2}, Lxk0/h;->A(Ljava/util/List;FFLl2/o;I)V

    .line 28
    .line 29
    .line 30
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_0
    iget-object v0, p0, Lh2/c;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lt2/b;

    .line 36
    .line 37
    check-cast p1, Ll2/o;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/16 p2, 0x1b7

    .line 45
    .line 46
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    iget v1, p0, Lh2/c;->e:F

    .line 51
    .line 52
    iget p0, p0, Lh2/c;->f:F

    .line 53
    .line 54
    invoke-static {v1, p0, v0, p1, p2}, Lh2/j;->b(FFLt2/b;Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
