.class public final synthetic Lfk/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/k;II)V
    .locals 0

    .line 1
    const/4 p4, 0x1

    iput p4, p0, Lfk/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p3, p0, Lfk/e;->e:I

    iput-object p2, p0, Lfk/e;->f:Lay0/k;

    iput-object p1, p0, Lfk/e;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lay0/a;I)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lfk/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lfk/e;->f:Lay0/k;

    iput-object p2, p0, Lfk/e;->g:Lay0/a;

    iput p3, p0, Lfk/e;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lfk/e;->d:I

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
    iget v0, p0, Lfk/e;->e:I

    .line 19
    .line 20
    iget-object v1, p0, Lfk/e;->f:Lay0/k;

    .line 21
    .line 22
    iget-object p0, p0, Lfk/e;->g:Lay0/a;

    .line 23
    .line 24
    invoke-static {v0, v1, p0, p1, p2}, Luz/k0;->M(ILay0/k;Lay0/a;Ll2/o;I)V

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
    iget p2, p0, Lfk/e;->e:I

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
    iget-object v0, p0, Lfk/e;->g:Lay0/a;

    .line 39
    .line 40
    iget-object p0, p0, Lfk/e;->f:Lay0/k;

    .line 41
    .line 42
    invoke-static {p2, v0, p0, p1}, Lfk/f;->d(ILay0/a;Lay0/k;Ll2/o;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
