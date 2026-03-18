.class public final Lkf0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Ljava/lang/String;)Llf0/j;
    .locals 8

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-input$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/16 v1, 0x11

    .line 11
    .line 12
    if-le v0, v1, :cond_0

    .line 13
    .line 14
    sget-object p0, Llf0/j;->h:Llf0/j;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    const-string v2, "TMBAAAAAAAA000000"

    .line 18
    .line 19
    invoke-virtual {v2, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    const-string v3, "substring(...)"

    .line 24
    .line 25
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    const-string v4, "(TMB|BSK)[A-HJ-NPR-Z\\d]{8}\\d{6}"

    .line 33
    .line 34
    invoke-static {v4}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    const-string v6, "compile(...)"

    .line 39
    .line 40
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v7, "input"

    .line 44
    .line 45
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v5, v2}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {v2}, Ljava/util/regex/Matcher;->matches()Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    const-string v5, "BSKAAAAAAAA000000"

    .line 57
    .line 58
    invoke-virtual {v5, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0, v5}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-static {v4}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    invoke-static {p0, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v3, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    or-int/2addr p0, v2

    .line 88
    if-eqz p0, :cond_2

    .line 89
    .line 90
    if-ne v0, v1, :cond_1

    .line 91
    .line 92
    sget-object p0, Llf0/j;->d:Llf0/j;

    .line 93
    .line 94
    return-object p0

    .line 95
    :cond_1
    sget-object p0, Llf0/j;->e:Llf0/j;

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_2
    if-ne v0, v1, :cond_3

    .line 99
    .line 100
    sget-object p0, Llf0/j;->f:Llf0/j;

    .line 101
    .line 102
    return-object p0

    .line 103
    :cond_3
    sget-object p0, Llf0/j;->g:Llf0/j;

    .line 104
    .line 105
    return-object p0
.end method


# virtual methods
.method public final synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Lss0/j0;

    .line 4
    .line 5
    iget-object p0, p0, Lss0/j0;->d:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0}, Lkf0/a;->a(Ljava/lang/String;)Llf0/j;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
