.class public final synthetic Li2/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Lg4/p0;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(JLg4/p0;Lay0/n;II)V
    .locals 0

    .line 1
    iput p6, p0, Li2/b1;->d:I

    .line 2
    .line 3
    iput-wide p1, p0, Li2/b1;->e:J

    .line 4
    .line 5
    iput-object p3, p0, Li2/b1;->f:Lg4/p0;

    .line 6
    .line 7
    iput-object p4, p0, Li2/b1;->g:Lay0/n;

    .line 8
    .line 9
    iput p5, p0, Li2/b1;->h:I

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
    iget v0, p0, Li2/b1;->d:I

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
    iget p1, p0, Li2/b1;->h:I

    .line 15
    .line 16
    or-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    iget-wide v1, p0, Li2/b1;->e:J

    .line 23
    .line 24
    iget-object v3, p0, Li2/b1;->f:Lg4/p0;

    .line 25
    .line 26
    iget-object v4, p0, Li2/b1;->g:Lay0/n;

    .line 27
    .line 28
    invoke-static/range {v1 .. v6}, Li2/h1;->b(JLg4/p0;Lay0/n;Ll2/o;I)V

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
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    iget p1, p0, Li2/b1;->h:I

    .line 43
    .line 44
    or-int/lit8 p1, p1, 0x1

    .line 45
    .line 46
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    iget-wide v0, p0, Li2/b1;->e:J

    .line 51
    .line 52
    iget-object v2, p0, Li2/b1;->f:Lg4/p0;

    .line 53
    .line 54
    iget-object v3, p0, Li2/b1;->g:Lay0/n;

    .line 55
    .line 56
    invoke-static/range {v0 .. v5}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

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
