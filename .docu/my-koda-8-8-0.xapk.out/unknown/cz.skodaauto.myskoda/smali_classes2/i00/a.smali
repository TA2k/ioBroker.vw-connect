.class public final synthetic Li00/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh00/b;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lh00/b;Lay0/a;Lay0/a;Lay0/a;II)V
    .locals 0

    .line 1
    iput p6, p0, Li00/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li00/a;->e:Lh00/b;

    .line 4
    .line 5
    iput-object p2, p0, Li00/a;->f:Lay0/a;

    .line 6
    .line 7
    iput-object p3, p0, Li00/a;->g:Lay0/a;

    .line 8
    .line 9
    iput-object p4, p0, Li00/a;->h:Lay0/a;

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
    .locals 7

    .line 1
    iget v0, p0, Li00/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/o;

    .line 8
    .line 9
    check-cast p2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const/16 p1, 0x9

    .line 15
    .line 16
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 17
    .line 18
    .line 19
    move-result v6

    .line 20
    iget-object v1, p0, Li00/a;->e:Lh00/b;

    .line 21
    .line 22
    iget-object v2, p0, Li00/a;->f:Lay0/a;

    .line 23
    .line 24
    iget-object v3, p0, Li00/a;->g:Lay0/a;

    .line 25
    .line 26
    iget-object v4, p0, Li00/a;->h:Lay0/a;

    .line 27
    .line 28
    invoke-static/range {v1 .. v6}, Li00/c;->c(Lh00/b;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    move-object v4, p1

    .line 35
    check-cast v4, Ll2/o;

    .line 36
    .line 37
    check-cast p2, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    const/16 p1, 0x9

    .line 43
    .line 44
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 45
    .line 46
    .line 47
    move-result v5

    .line 48
    iget-object v0, p0, Li00/a;->e:Lh00/b;

    .line 49
    .line 50
    iget-object v1, p0, Li00/a;->f:Lay0/a;

    .line 51
    .line 52
    iget-object v2, p0, Li00/a;->g:Lay0/a;

    .line 53
    .line 54
    iget-object v3, p0, Li00/a;->h:Lay0/a;

    .line 55
    .line 56
    invoke-static/range {v0 .. v5}, Li00/c;->c(Lh00/b;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
