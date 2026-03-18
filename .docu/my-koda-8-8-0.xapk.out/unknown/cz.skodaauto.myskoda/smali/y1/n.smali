.class public final synthetic Ly1/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ly1/o;

.field public final synthetic f:Landroid/graphics/drawable/Icon;


# direct methods
.method public synthetic constructor <init>(Ly1/o;Landroid/graphics/drawable/Icon;II)V
    .locals 0

    .line 1
    iput p4, p0, Ly1/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ly1/n;->e:Ly1/o;

    .line 4
    .line 5
    iput-object p2, p0, Ly1/n;->f:Landroid/graphics/drawable/Icon;

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
    iget v0, p0, Ly1/n;->d:I

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
    iget-object v0, p0, Ly1/n;->e:Ly1/o;

    .line 20
    .line 21
    iget-object p0, p0, Ly1/n;->f:Landroid/graphics/drawable/Icon;

    .line 22
    .line 23
    invoke-virtual {v0, p0, p1, p2}, Ly1/o;->b(Landroid/graphics/drawable/Icon;Ll2/o;I)V

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
    iget-object v0, p0, Ly1/n;->e:Ly1/o;

    .line 36
    .line 37
    iget-object p0, p0, Ly1/n;->f:Landroid/graphics/drawable/Icon;

    .line 38
    .line 39
    invoke-virtual {v0, p0, p1, p2}, Ly1/o;->b(Landroid/graphics/drawable/Icon;Ll2/o;I)V

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
