.class public final Lp60/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/text/Collator;


# direct methods
.method public constructor <init>()V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Lp60/h;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    invoke-static {}, Ljava/text/Collator;->getInstance()Ljava/text/Collator;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/text/Collator;->setStrength(I)V

    iput-object v0, p0, Lp60/h;->e:Ljava/text/Collator;

    return-void
.end method

.method public constructor <init>(Ljava/text/Collator;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lp60/h;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lp60/h;->e:Ljava/text/Collator;

    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Lp60/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lxz/a;

    .line 7
    .line 8
    iget-object p1, p1, Lxz/a;->b:Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, Lp60/h;->e:Ljava/text/Collator;

    .line 11
    .line 12
    invoke-virtual {p0, p1}, Ljava/text/Collator;->getCollationKey(Ljava/lang/String;)Ljava/text/CollationKey;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    check-cast p2, Lxz/a;

    .line 17
    .line 18
    iget-object p2, p2, Lxz/a;->b:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, p2}, Ljava/text/Collator;->getCollationKey(Ljava/lang/String;)Ljava/text/CollationKey;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p1, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0

    .line 29
    :pswitch_0
    check-cast p1, Lq60/b;

    .line 30
    .line 31
    check-cast p2, Lq60/b;

    .line 32
    .line 33
    const/4 v0, 0x0

    .line 34
    if-eqz p1, :cond_0

    .line 35
    .line 36
    iget-object p1, p1, Lq60/b;->b:Ljava/lang/String;

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move-object p1, v0

    .line 40
    :goto_0
    if-eqz p2, :cond_1

    .line 41
    .line 42
    iget-object v0, p2, Lq60/b;->b:Ljava/lang/String;

    .line 43
    .line 44
    :cond_1
    iget-object p0, p0, Lp60/h;->e:Ljava/text/Collator;

    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Ljava/text/Collator;->compare(Ljava/lang/String;Ljava/lang/String;)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    return p0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
