.class public final synthetic Ld70/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lc70/d;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Lc70/d;Lx2/s;Lay0/a;II)V
    .locals 0

    .line 1
    const/4 p4, 0x0

    iput p4, p0, Ld70/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld70/a;->f:Lc70/d;

    iput-object p2, p0, Ld70/a;->e:Lx2/s;

    iput-object p3, p0, Ld70/a;->g:Lay0/a;

    iput p5, p0, Ld70/a;->h:I

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Lc70/d;Lay0/a;I)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ld70/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld70/a;->e:Lx2/s;

    iput-object p2, p0, Ld70/a;->f:Lc70/d;

    iput-object p3, p0, Ld70/a;->g:Lay0/a;

    iput p4, p0, Ld70/a;->h:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Ld70/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Integer;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget p2, p0, Ld70/a;->h:I

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
    iget-object v0, p0, Ld70/a;->e:Lx2/s;

    .line 22
    .line 23
    iget-object v1, p0, Ld70/a;->f:Lc70/d;

    .line 24
    .line 25
    iget-object p0, p0, Ld70/a;->g:Lay0/a;

    .line 26
    .line 27
    invoke-static {v0, v1, p0, p1, p2}, Ljp/sf;->a(Lx2/s;Lc70/d;Lay0/a;Ll2/o;I)V

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
    move-object v3, p1

    .line 34
    check-cast v3, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    iget-object v0, p0, Ld70/a;->f:Lc70/d;

    .line 47
    .line 48
    iget-object v1, p0, Ld70/a;->e:Lx2/s;

    .line 49
    .line 50
    iget-object v2, p0, Ld70/a;->g:Lay0/a;

    .line 51
    .line 52
    iget v5, p0, Ld70/a;->h:I

    .line 53
    .line 54
    invoke-static/range {v0 .. v5}, Ljp/sf;->c(Lc70/d;Lx2/s;Lay0/a;Ll2/o;II)V

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
