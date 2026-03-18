.class public final Lfw0/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lfw0/z;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget p0, p0, Lfw0/z;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p2, Llx0/l;

    .line 7
    .line 8
    iget-object p0, p2, Llx0/l;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/lang/Float;

    .line 11
    .line 12
    check-cast p1, Llx0/l;

    .line 13
    .line 14
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Ljava/lang/Float;

    .line 17
    .line 18
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :pswitch_0
    check-cast p1, Ljava/nio/charset/Charset;

    .line 24
    .line 25
    invoke-static {p1}, Ljp/q1;->c(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p2, Ljava/nio/charset/Charset;

    .line 30
    .line 31
    invoke-static {p2}, Ljp/q1;->c(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
