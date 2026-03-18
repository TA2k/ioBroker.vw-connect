.class public final synthetic Lh2/e5;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lx2/s;

.field public final synthetic g:J

.field public final synthetic h:I

.field public final synthetic i:I

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/String;Lx2/s;JIII)V
    .locals 0

    .line 1
    iput p8, p0, Lh2/e5;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/e5;->j:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/e5;->e:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/e5;->f:Lx2/s;

    .line 8
    .line 9
    iput-wide p4, p0, Lh2/e5;->g:J

    .line 10
    .line 11
    iput p6, p0, Lh2/e5;->h:I

    .line 12
    .line 13
    iput p7, p0, Lh2/e5;->i:I

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh2/e5;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/e5;->j:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Lj3/f;

    .line 10
    .line 11
    move-object v6, p1

    .line 12
    check-cast v6, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget p1, p0, Lh2/e5;->h:I

    .line 20
    .line 21
    or-int/lit8 p1, p1, 0x1

    .line 22
    .line 23
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 24
    .line 25
    .line 26
    move-result v7

    .line 27
    iget-object v2, p0, Lh2/e5;->e:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v3, p0, Lh2/e5;->f:Lx2/s;

    .line 30
    .line 31
    iget-wide v4, p0, Lh2/e5;->g:J

    .line 32
    .line 33
    iget v8, p0, Lh2/e5;->i:I

    .line 34
    .line 35
    invoke-static/range {v1 .. v8}, Lh2/f5;->b(Lj3/f;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 36
    .line 37
    .line 38
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object v0, p0, Lh2/e5;->j:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v1, v0

    .line 44
    check-cast v1, Li3/c;

    .line 45
    .line 46
    move-object v6, p1

    .line 47
    check-cast v6, Ll2/o;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    iget p1, p0, Lh2/e5;->h:I

    .line 55
    .line 56
    or-int/lit8 p1, p1, 0x1

    .line 57
    .line 58
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 59
    .line 60
    .line 61
    move-result v7

    .line 62
    iget-object v2, p0, Lh2/e5;->e:Ljava/lang/String;

    .line 63
    .line 64
    iget-object v3, p0, Lh2/e5;->f:Lx2/s;

    .line 65
    .line 66
    iget-wide v4, p0, Lh2/e5;->g:J

    .line 67
    .line 68
    iget v8, p0, Lh2/e5;->i:I

    .line 69
    .line 70
    invoke-static/range {v1 .. v8}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
