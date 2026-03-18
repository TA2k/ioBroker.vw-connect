.class public final Lsl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:Ljava/lang/Object;

.field public final c:J

.field public final d:J

.field public final e:Z

.field public final f:Ld01/y;


# direct methods
.method public constructor <init>(Ld01/t0;)V
    .locals 3

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    sget-object v0, Llx0/j;->f:Llx0/j;

    new-instance v1, Lsl/a;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Lsl/a;-><init>(Lsl/b;I)V

    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v1

    iput-object v1, p0, Lsl/b;->a:Ljava/lang/Object;

    .line 21
    new-instance v1, Lsl/a;

    const/4 v2, 0x1

    invoke-direct {v1, p0, v2}, Lsl/a;-><init>(Lsl/b;I)V

    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v0

    iput-object v0, p0, Lsl/b;->b:Ljava/lang/Object;

    .line 22
    iget-wide v0, p1, Ld01/t0;->o:J

    .line 23
    iput-wide v0, p0, Lsl/b;->c:J

    .line 24
    iget-wide v0, p1, Ld01/t0;->p:J

    .line 25
    iput-wide v0, p0, Lsl/b;->d:J

    .line 26
    iget-object v0, p1, Ld01/t0;->h:Ld01/w;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    .line 27
    :goto_0
    iput-boolean v0, p0, Lsl/b;->e:Z

    .line 28
    iget-object p1, p1, Ld01/t0;->i:Ld01/y;

    .line 29
    iput-object p1, p0, Lsl/b;->f:Ld01/y;

    return-void
.end method

.method public constructor <init>(Lu01/b0;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Llx0/j;->f:Llx0/j;

    new-instance v1, Lsl/a;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Lsl/a;-><init>(Lsl/b;I)V

    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v1

    iput-object v1, p0, Lsl/b;->a:Ljava/lang/Object;

    .line 3
    new-instance v1, Lsl/a;

    const/4 v3, 0x1

    invoke-direct {v1, p0, v3}, Lsl/a;-><init>(Lsl/b;I)V

    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v0

    iput-object v0, p0, Lsl/b;->b:Ljava/lang/Object;

    const-wide v0, 0x7fffffffffffffffL

    .line 4
    invoke-virtual {p1, v0, v1}, Lu01/b0;->x(J)Ljava/lang/String;

    move-result-object v4

    .line 5
    invoke-static {v4}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v4

    iput-wide v4, p0, Lsl/b;->c:J

    .line 6
    invoke-virtual {p1, v0, v1}, Lu01/b0;->x(J)Ljava/lang/String;

    move-result-object v4

    .line 7
    invoke-static {v4}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v4

    iput-wide v4, p0, Lsl/b;->d:J

    .line 8
    invoke-virtual {p1, v0, v1}, Lu01/b0;->x(J)Ljava/lang/String;

    move-result-object v4

    .line 9
    invoke-static {v4}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v4

    if-lez v4, :cond_0

    goto :goto_0

    :cond_0
    move v3, v2

    :goto_0
    iput-boolean v3, p0, Lsl/b;->e:Z

    .line 10
    invoke-virtual {p1, v0, v1}, Lu01/b0;->x(J)Ljava/lang/String;

    move-result-object v3

    .line 11
    invoke-static {v3}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v3

    .line 12
    new-instance v4, Ld01/x;

    invoke-direct {v4, v2, v2}, Ld01/x;-><init>(BI)V

    move v5, v2

    :goto_1
    if-ge v5, v3, :cond_2

    .line 13
    invoke-virtual {p1, v0, v1}, Lu01/b0;->x(J)Ljava/lang/String;

    move-result-object v6

    .line 14
    sget-object v7, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    const/16 v7, 0x3a

    const/4 v8, 0x6

    .line 15
    invoke-static {v6, v7, v2, v8}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    move-result v7

    const/4 v8, -0x1

    if-eq v7, v8, :cond_1

    .line 16
    invoke-virtual {v6, v2, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v8

    const-string v9, "this as java.lang.String\u2026ing(startIndex, endIndex)"

    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v8}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    move-result-object v8

    invoke-virtual {v8}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v8

    add-int/lit8 v7, v7, 0x1

    invoke-virtual {v6, v7}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v6

    const-string v7, "this as java.lang.String).substring(startIndex)"

    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v4, v8, v6}, Ld01/x;->h(Ljava/lang/String;Ljava/lang/String;)V

    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    .line 17
    :cond_1
    const-string p0, "Unexpected header: "

    invoke-virtual {p0, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    .line 18
    :cond_2
    invoke-virtual {v4}, Ld01/x;->j()Ld01/y;

    move-result-object p1

    iput-object p1, p0, Lsl/b;->f:Ld01/y;

    return-void
.end method


# virtual methods
.method public final a(Lu01/a0;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lsl/b;->c:J

    .line 2
    .line 3
    invoke-virtual {p1, v0, v1}, Lu01/a0;->N(J)Lu01/g;

    .line 4
    .line 5
    .line 6
    const/16 v0, 0xa

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 9
    .line 10
    .line 11
    iget-wide v1, p0, Lsl/b;->d:J

    .line 12
    .line 13
    invoke-virtual {p1, v1, v2}, Lu01/a0;->N(J)Lu01/g;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1, v0}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 17
    .line 18
    .line 19
    iget-boolean v1, p0, Lsl/b;->e:Z

    .line 20
    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const-wide/16 v1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const-wide/16 v1, 0x0

    .line 27
    .line 28
    :goto_0
    invoke-virtual {p1, v1, v2}, Lu01/a0;->N(J)Lu01/g;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1, v0}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lsl/b;->f:Ld01/y;

    .line 35
    .line 36
    invoke-virtual {p0}, Ld01/y;->size()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    int-to-long v1, v1

    .line 41
    invoke-virtual {p1, v1, v2}, Lu01/a0;->N(J)Lu01/g;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1, v0}, Lu01/a0;->writeByte(I)Lu01/g;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Ld01/y;->size()I

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    const/4 v2, 0x0

    .line 52
    :goto_1
    if-ge v2, v1, :cond_1

    .line 53
    .line 54
    invoke-virtual {p0, v2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    invoke-virtual {p1, v3}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 59
    .line 60
    .line 61
    const-string v3, ": "

    .line 62
    .line 63
    invoke-virtual {p1, v3}, Lu01/a0;->z(Ljava/lang/String;)Lu01/g;

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-interface {p1, v3}, Lu01/g;->z(Ljava/lang/String;)Lu01/g;

    .line 71
    .line 72
    .line 73
    invoke-interface {p1, v0}, Lu01/g;->writeByte(I)Lu01/g;

    .line 74
    .line 75
    .line 76
    add-int/lit8 v2, v2, 0x1

    .line 77
    .line 78
    goto :goto_1

    .line 79
    :cond_1
    return-void
.end method
