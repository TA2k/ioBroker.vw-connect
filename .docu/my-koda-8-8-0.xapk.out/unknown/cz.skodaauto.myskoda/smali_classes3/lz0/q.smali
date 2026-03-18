.class public final Llz0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llz0/m;


# instance fields
.field public final a:Lh2/y5;

.field public final b:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lh2/y5;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "whatThisExpects"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Llz0/q;->a:Lh2/y5;

    .line 10
    .line 11
    iput-object p2, p0, Llz0/q;->b:Ljava/lang/String;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Llz0/c;Ljava/lang/CharSequence;I)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-lt p3, v0, :cond_0

    .line 11
    .line 12
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    invoke-interface {p2, p3}, Ljava/lang/CharSequence;->charAt(I)C

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    const/16 v0, 0x2d

    .line 22
    .line 23
    iget-object v1, p0, Llz0/q;->a:Lh2/y5;

    .line 24
    .line 25
    if-ne p2, v0, :cond_1

    .line 26
    .line 27
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 28
    .line 29
    invoke-virtual {v1, p1, p0}, Lh2/y5;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    add-int/lit8 p3, p3, 0x1

    .line 33
    .line 34
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_1
    const/16 v0, 0x2b

    .line 40
    .line 41
    if-ne p2, v0, :cond_2

    .line 42
    .line 43
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 44
    .line 45
    invoke-virtual {v1, p1, p0}, Lh2/y5;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    add-int/lit8 p3, p3, 0x1

    .line 49
    .line 50
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :cond_2
    new-instance p1, Llz0/p;

    .line 56
    .line 57
    invoke-direct {p1, p0, p2}, Llz0/p;-><init>(Llz0/q;C)V

    .line 58
    .line 59
    .line 60
    new-instance p0, Llz0/h;

    .line 61
    .line 62
    invoke-direct {p0, p3, p1}, Llz0/h;-><init>(ILay0/a;)V

    .line 63
    .line 64
    .line 65
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Llz0/q;->b:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
