.class public final synthetic Lh2/y3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Ljava/lang/Long;

.field public final synthetic e:Ljava/lang/Long;

.field public final synthetic f:J

.field public final synthetic g:Lay0/n;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Li2/z;

.field public final synthetic j:Lgy0/j;

.field public final synthetic k:Lh2/g2;

.field public final synthetic l:Lh2/e8;

.field public final synthetic m:Lh2/z1;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Long;Ljava/lang/Long;JLay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/y3;->d:Ljava/lang/Long;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/y3;->e:Ljava/lang/Long;

    .line 7
    .line 8
    iput-wide p3, p0, Lh2/y3;->f:J

    .line 9
    .line 10
    iput-object p5, p0, Lh2/y3;->g:Lay0/n;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/y3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/y3;->i:Li2/z;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/y3;->j:Lgy0/j;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/y3;->k:Lh2/g2;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/y3;->l:Lh2/e8;

    .line 21
    .line 22
    iput-object p11, p0, Lh2/y3;->m:Lh2/z1;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v11, p1

    .line 2
    check-cast v11, Ll2/o;

    .line 3
    .line 4
    check-cast p2, Ljava/lang/Integer;

    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 11
    .line 12
    .line 13
    move-result v12

    .line 14
    iget-object v0, p0, Lh2/y3;->d:Ljava/lang/Long;

    .line 15
    .line 16
    iget-object v1, p0, Lh2/y3;->e:Ljava/lang/Long;

    .line 17
    .line 18
    iget-wide v2, p0, Lh2/y3;->f:J

    .line 19
    .line 20
    iget-object v4, p0, Lh2/y3;->g:Lay0/n;

    .line 21
    .line 22
    iget-object v5, p0, Lh2/y3;->h:Lay0/k;

    .line 23
    .line 24
    iget-object v6, p0, Lh2/y3;->i:Li2/z;

    .line 25
    .line 26
    iget-object v7, p0, Lh2/y3;->j:Lgy0/j;

    .line 27
    .line 28
    iget-object v8, p0, Lh2/y3;->k:Lh2/g2;

    .line 29
    .line 30
    iget-object v9, p0, Lh2/y3;->l:Lh2/e8;

    .line 31
    .line 32
    iget-object v10, p0, Lh2/y3;->m:Lh2/z1;

    .line 33
    .line 34
    invoke-static/range {v0 .. v12}, Lh2/f4;->b(Ljava/lang/Long;Ljava/lang/Long;JLay0/n;Lay0/k;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Ll2/o;I)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0
.end method
