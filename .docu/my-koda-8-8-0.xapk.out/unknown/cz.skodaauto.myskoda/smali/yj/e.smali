.class public final synthetic Lyj/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lkd/n;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Lkd/n;Lay0/k;II)V
    .locals 0

    .line 1
    iput p4, p0, Lyj/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lyj/e;->e:Lkd/n;

    .line 4
    .line 5
    iput-object p2, p0, Lyj/e;->f:Lay0/k;

    .line 6
    .line 7
    iput p3, p0, Lyj/e;->g:I

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lyj/e;->d:I

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
    iget p2, p0, Lyj/e;->g:I

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
    iget-object v0, p0, Lyj/e;->e:Lkd/n;

    .line 22
    .line 23
    iget-object p0, p0, Lyj/e;->f:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, p0, p1, p2}, Lyj/f;->e(Lkd/n;Lay0/k;Ll2/o;I)V

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    iget p2, p0, Lyj/e;->g:I

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
    iget-object v0, p0, Lyj/e;->e:Lkd/n;

    .line 43
    .line 44
    iget-object p0, p0, Lyj/e;->f:Lay0/k;

    .line 45
    .line 46
    invoke-static {v0, p0, p1, p2}, Lyj/f;->d(Lkd/n;Lay0/k;Ll2/o;I)V

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
