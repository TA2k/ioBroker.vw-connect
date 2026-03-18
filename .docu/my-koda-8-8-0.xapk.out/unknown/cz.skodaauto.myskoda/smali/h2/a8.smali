.class public final Lh2/a8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lay0/o;

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lay0/n;

.field public final synthetic i:Li2/x0;

.field public final synthetic j:Lay0/n;


# direct methods
.method public constructor <init>(ILay0/n;Lay0/o;Lay0/n;Lay0/n;Li2/x0;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/a8;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lh2/a8;->e:Lay0/n;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/a8;->f:Lay0/o;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/a8;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/a8;->h:Lay0/n;

    .line 13
    .line 14
    iput-object p6, p0, Lh2/a8;->i:Li2/x0;

    .line 15
    .line 16
    iput-object p7, p0, Lh2/a8;->j:Lay0/n;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x1

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    move v0, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    and-int/2addr p2, v2

    .line 19
    move-object v8, p1

    .line 20
    check-cast v8, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    iget-object v7, p0, Lh2/a8;->j:Lay0/n;

    .line 29
    .line 30
    const/4 v9, 0x0

    .line 31
    iget v1, p0, Lh2/a8;->d:I

    .line 32
    .line 33
    iget-object v2, p0, Lh2/a8;->e:Lay0/n;

    .line 34
    .line 35
    iget-object v3, p0, Lh2/a8;->f:Lay0/o;

    .line 36
    .line 37
    iget-object v4, p0, Lh2/a8;->g:Lay0/n;

    .line 38
    .line 39
    iget-object v5, p0, Lh2/a8;->h:Lay0/n;

    .line 40
    .line 41
    iget-object v6, p0, Lh2/a8;->i:Li2/x0;

    .line 42
    .line 43
    invoke-static/range {v1 .. v9}, Lh2/c8;->b(ILay0/n;Lay0/o;Lay0/n;Lay0/n;Lk1/q1;Lay0/n;Ll2/o;I)V

    .line 44
    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 48
    .line 49
    .line 50
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0
.end method
