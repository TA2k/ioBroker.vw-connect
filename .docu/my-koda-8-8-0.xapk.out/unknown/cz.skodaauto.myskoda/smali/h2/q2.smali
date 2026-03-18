.class public final synthetic Lh2/q2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lx2/s;

.field public final synthetic e:J

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Lh2/e8;

.field public final synthetic h:Li2/z;

.field public final synthetic i:Lgy0/j;

.field public final synthetic j:Lh2/z1;


# direct methods
.method public synthetic constructor <init>(Lx2/s;JLay0/k;Lh2/e8;Li2/z;Lgy0/j;Lh2/z1;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/q2;->d:Lx2/s;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/q2;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lh2/q2;->f:Lay0/k;

    .line 9
    .line 10
    iput-object p5, p0, Lh2/q2;->g:Lh2/e8;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/q2;->h:Li2/z;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/q2;->i:Lgy0/j;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/q2;->j:Lh2/z1;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    move-object v8, p1

    .line 2
    check-cast v8, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x7

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v9

    .line 14
    iget-object v0, p0, Lh2/q2;->d:Lx2/s;

    .line 15
    .line 16
    iget-wide v1, p0, Lh2/q2;->e:J

    .line 17
    .line 18
    iget-object v3, p0, Lh2/q2;->f:Lay0/k;

    .line 19
    .line 20
    iget-object v4, p0, Lh2/q2;->g:Lh2/e8;

    .line 21
    .line 22
    iget-object v5, p0, Lh2/q2;->h:Li2/z;

    .line 23
    .line 24
    iget-object v6, p0, Lh2/q2;->i:Lgy0/j;

    .line 25
    .line 26
    iget-object v7, p0, Lh2/q2;->j:Lh2/z1;

    .line 27
    .line 28
    invoke-static/range {v0 .. v9}, Lh2/m3;->n(Lx2/s;JLay0/k;Lh2/e8;Li2/z;Lgy0/j;Lh2/z1;Ll2/o;I)V

    .line 29
    .line 30
    .line 31
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0
.end method
