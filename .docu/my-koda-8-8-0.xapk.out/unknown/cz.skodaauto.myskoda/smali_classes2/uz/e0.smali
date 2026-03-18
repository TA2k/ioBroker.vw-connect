.class public final synthetic Luz/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Z

.field public final synthetic g:Lay0/a;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(IILay0/a;Ljava/lang/String;Z)V
    .locals 0

    .line 1
    iput p2, p0, Luz/e0;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Luz/e0;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-boolean p5, p0, Luz/e0;->f:Z

    .line 6
    .line 7
    iput-object p3, p0, Luz/e0;->g:Lay0/a;

    .line 8
    .line 9
    iput p1, p0, Luz/e0;->h:I

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Luz/e0;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget p2, p0, Luz/e0;->h:I

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
    iget-object v0, p0, Luz/e0;->g:Lay0/a;

    .line 22
    .line 23
    iget-object v1, p0, Luz/e0;->e:Ljava/lang/String;

    .line 24
    .line 25
    iget-boolean p0, p0, Luz/e0;->f:Z

    .line 26
    .line 27
    invoke-static {p2, v0, v1, p1, p0}, Lyc0/a;->f(ILay0/a;Ljava/lang/String;Ll2/o;Z)V

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
    iget p2, p0, Luz/e0;->h:I

    .line 34
    .line 35
    or-int/lit8 p2, p2, 0x1

    .line 36
    .line 37
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    iget-object v0, p0, Luz/e0;->g:Lay0/a;

    .line 42
    .line 43
    iget-object v1, p0, Luz/e0;->e:Ljava/lang/String;

    .line 44
    .line 45
    iget-boolean p0, p0, Luz/e0;->f:Z

    .line 46
    .line 47
    invoke-static {p2, v0, v1, p1, p0}, Luz/f0;->c(ILay0/a;Ljava/lang/String;Ll2/o;Z)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
